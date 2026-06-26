#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "bpf.h"
#include "capture.h"
#include "filter.h"
#include "packet.h"
#include "pcap.h"

int capture_linktype(unsigned short hw_type, unsigned int *linktype)
{
  switch (hw_type) {
  case ARPHRD_ETHER:
  case ARPHRD_LOOPBACK:
    *linktype = PCAP_LINKTYPE_EN10MB;
    return 0;
  case ARPHRD_IEEE80211:
    *linktype = PCAP_LINKTYPE_IEEE802_11;
    return 0;
  case ARPHRD_IEEE80211_PRISM:
    *linktype = PCAP_LINKTYPE_PRISM_HEADER;
    return 0;
  case ARPHRD_IEEE80211_RADIOTAP:
    *linktype = PCAP_LINKTYPE_IEEE802_11_RADIO;
    return 0;
  default:
    return -1;
  }
}

static const char *linktype_name(unsigned int linktype)
{
  switch (linktype) {
  case PCAP_LINKTYPE_EN10MB:
    return "EN10MB (Ethernet)";
  case PCAP_LINKTYPE_IEEE802_11:
    return "IEEE802_11 (802.11)";
  case PCAP_LINKTYPE_PRISM_HEADER:
    return "PRISM_HEADER (802.11 plus Prism header)";
  case PCAP_LINKTYPE_IEEE802_11_RADIO:
    return "IEEE802_11_RADIO (802.11 plus radiotap header)";
  default:
    return "UNKNOWN";
  }
}

void capture_banner(const char *progname, const char *ifname,
    unsigned int linktype, unsigned int snaplen)
{
  fprintf(stderr, "%s: listening on %s, link-type %s, snapshot length %u bytes\n",
      progname, ifname, linktype_name(linktype), snaplen);
}

static int now_ms(unsigned long long *out)
{
  struct timespec ts;

  if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0) {
    perror("clock_gettime");
    return -1;
  }

  *out = (unsigned long long)ts.tv_sec * 1000ull +
      (unsigned long long)ts.tv_nsec / 1000000ull;
  return 0;
}

static int get_link_type(unsigned int ifindex, unsigned short *hw_type)
{
  struct {
    struct nlmsghdr nlh;
    struct ifinfomsg ifm;
  } req;
  struct sockaddr_nl addr;
  struct timeval tv;
  unsigned char buf[8192];
  struct nlmsghdr *nlh;
  ssize_t len;
  int fd;

  fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
  if (fd < 0) {
    perror("socket(AF_NETLINK)");
    return -1;
  }

  memset(&addr, 0, sizeof(addr));
  addr.nl_family = AF_NETLINK;
  if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    perror("bind(AF_NETLINK)");
    close(fd);
    return -1;
  }

  tv.tv_sec = 0;
  tv.tv_usec = 100000;
  if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
    perror("setsockopt(SO_RCVTIMEO)");
    close(fd);
    return -1;
  }

  memset(&req, 0, sizeof(req));
  req.nlh.nlmsg_len = sizeof(req);
  req.nlh.nlmsg_type = RTM_GETLINK;
  req.nlh.nlmsg_flags = NLM_F_REQUEST;
  req.nlh.nlmsg_seq = 1;
  req.nlh.nlmsg_pid = getpid();
  req.ifm.ifi_family = AF_UNSPEC;
  req.ifm.ifi_index = (int)ifindex;

  memset(&addr, 0, sizeof(addr));
  addr.nl_family = AF_NETLINK;
  if (sendto(fd, &req, req.nlh.nlmsg_len, 0,
      (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    perror("sendto(RTM_GETLINK)");
    close(fd);
    return -1;
  }

  for (;;) {
    len = recv(fd, buf, sizeof(buf), 0);
    if (len < 0) {
      if (errno == EINTR)
        continue;
      perror("recv(RTM_GETLINK)");
      close(fd);
      return -1;
    }

    for (nlh = (struct nlmsghdr *)buf; NLMSG_OK(nlh, len);
        nlh = NLMSG_NEXT(nlh, len)) {
      struct ifinfomsg *ifm;

      if (nlh->nlmsg_seq != req.nlh.nlmsg_seq)
        continue;
      if (nlh->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *err;

        if (nlh->nlmsg_len < NLMSG_LENGTH(sizeof(*err))) {
          errno = EPROTO;
          perror("RTM_GETLINK");
          close(fd);
          return -1;
        }
        err = NLMSG_DATA(nlh);
        if (!err->error)
          continue;
        errno = -err->error;
        perror("RTM_GETLINK");
        close(fd);
        return -1;
      }
      if (nlh->nlmsg_type != RTM_NEWLINK)
        continue;
      if (nlh->nlmsg_len < NLMSG_LENGTH(sizeof(*ifm))) {
        errno = EPROTO;
        perror("RTM_GETLINK");
        close(fd);
        return -1;
      }

      ifm = NLMSG_DATA(nlh);
      if (ifm->ifi_index != (int)ifindex)
        continue;

      *hw_type = ifm->ifi_type;
      close(fd);
      return 0;
    }
  }
}

static int open_socket(unsigned int ifindex)
{
  struct sockaddr_ll sll;
  int fd;

  fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (fd < 0) {
    perror("socket");
    return -1;
  }

  memset(&sll, 0, sizeof(sll));
  sll.sll_family = AF_PACKET;
  sll.sll_protocol = htons(ETH_P_ALL);
  sll.sll_ifindex = (int)ifindex;

  if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
    perror("bind");
    close(fd);
    return -1;
  }

  return fd;
}

static int wait_packet(int fd, unsigned long long deadline_ms)
{
  struct pollfd pfd;
  unsigned long long now;
  unsigned long long delta;
  int timeout_ms;
  int ret;

  if (!deadline_ms)
    return 1;

  if (now_ms(&now) < 0)
    return -1;

  if (now >= deadline_ms)
    return 0;

  delta = deadline_ms - now;
  if (delta > (unsigned long long)INT_MAX)
    timeout_ms = INT_MAX;
  else
    timeout_ms = (int)delta;

  pfd.fd = fd;
  pfd.events = POLLIN;
  pfd.revents = 0;

  ret = poll(&pfd, 1, timeout_ms);
  if (ret < 0) {
    if (errno == EINTR)
      return 1;
    perror("poll");
    return -1;
  }

  return ret;
}

static int attach_bpf(int fd, const struct filter *f)
{
  struct sock_fprog fprog;
  struct bpf_prog prog;

  if (!f || !f->root)
    return 0;

  if (bpf_compile(&prog, f) < 0)
    return -1;

  fprog = bpf_sock_fprog(&prog);
  if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &fprog, sizeof(fprog)) < 0) {
    perror("setsockopt(SO_ATTACH_FILTER)");
    bpf_prog_free(&prog);
    return -1;
  }

  bpf_prog_free(&prog);
  return 0;
}

int capture_run(const struct capture_cfg *cfg)
{
  unsigned char *buf;
  unsigned int linktype;
  unsigned int ifindex;
  unsigned int snaplen;
  unsigned short hw_type;
  struct pkt_info pi;
  struct pcap_writer pw;
  struct timespec ts;
  unsigned long long deadline_ms;
  unsigned long long seen;
  ssize_t len;
  int ready;
  int fd;
  int rc;

  snaplen = cfg->snaplen ? cfg->snaplen : PCAP_SNAPLEN;

  buf = malloc(snaplen);
  if (!buf) {
    perror("malloc");
    return -1;
  }

  ifindex = if_nametoindex(cfg->ifname);
  if (!ifindex) {
    fprintf(stderr, "unknown interface: %s\n", cfg->ifname);
    rc = -1;
    goto out;
  }

  if (get_link_type(ifindex, &hw_type) < 0) {
    rc = -1;
    goto out;
  }

  if (capture_linktype(hw_type, &linktype) < 0) {
    fprintf(stderr, "unsupported interface type %u on %s\n",
        hw_type, cfg->ifname);
    rc = -1;
    goto out;
  }

  if (pcap_open(&pw, cfg->out_path, snaplen, linktype) < 0) {
    rc = -1;
    goto out;
  }

  fd = open_socket(ifindex);
  if (fd < 0) {
    pcap_close(&pw);
    rc = -1;
    goto out;
  }

  if (cfg->filter_mode == FILTER_MODE_BPF &&
      attach_bpf(fd, cfg->filter) < 0) {
    close(fd);
    pcap_close(&pw);
    rc = -1;
    goto out;
  }

  capture_banner(cfg->progname ? cfg->progname : "udump", cfg->ifname,
      linktype, snaplen);

  deadline_ms = 0;
  if (cfg->time_limit) {
    if (now_ms(&deadline_ms) < 0) {
      close(fd);
      pcap_close(&pw);
      rc = -1;
      goto out;
    }
    deadline_ms += (unsigned long long)cfg->time_limit * 1000ull;
  }

  seen = 0;
  for (;;) {
    ready = wait_packet(fd, deadline_ms);
    if (ready < 0) {
      close(fd);
      pcap_close(&pw);
      rc = -1;
      goto out;
    }

    if (!ready)
      break;

    len = recvfrom(fd, buf, snaplen, 0, NULL, NULL);
    if (len < 0) {
      if (errno == EINTR)
        continue;
      perror("recvfrom");
      close(fd);
      pcap_close(&pw);
      rc = -1;
      goto out;
    }

    if (cfg->filter_mode == FILTER_MODE_USER &&
        cfg->filter && cfg->filter->root) {
      if (packet_parse(&pi, buf, (unsigned int)len) < 0)
        continue;
      if (!filter_match(cfg->filter, &pi))
        continue;
    }

    if (clock_gettime(CLOCK_REALTIME, &ts) < 0) {
      perror("clock_gettime");
      close(fd);
      pcap_close(&pw);
      rc = -1;
      goto out;
    }

    if (pcap_write_packet(&pw, &ts, buf, (unsigned int)len,
        (unsigned int)len) < 0) {
      close(fd);
      pcap_close(&pw);
      rc = -1;
      goto out;
    }

    seen++;
    if (cfg->pkt_limit && seen >= cfg->pkt_limit)
      break;
  }

  if (close(fd) < 0) {
    perror("close");
    pcap_close(&pw);
    rc = -1;
    goto out;
  }

  if (pcap_close(&pw) < 0) {
    rc = -1;
    goto out;
  }

  rc = 0;
out:
  free(buf);
  return rc;
}
