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

#define SLL2_HDR_LEN 20u

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
  case PCAP_LINKTYPE_LINUX_SLL2:
    return "LINUX_SLL2 (Linux cooked v2)";
  default:
    return "UNKNOWN";
  }
}

void capture_banner(const char *progname, const char *ifname,
    unsigned int linktype, unsigned int snaplen)
{
  if (!strcmp(ifname, "any") && linktype == PCAP_LINKTYPE_LINUX_SLL2)
    fprintf(stderr, "%s: data link type LINUX_SLL2\n", progname);
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

static int open_socket(unsigned int ifindex, int cooked)
{
  struct sockaddr_ll sll;
  int fd;

  fd = socket(AF_PACKET, cooked ? SOCK_DGRAM : SOCK_RAW, htons(ETH_P_ALL));
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

static void put_be16(unsigned char *dst, unsigned int val)
{
  dst[0] = (unsigned char)((val >> 8) & 0xff);
  dst[1] = (unsigned char)(val & 0xff);
}

static void put_be32(unsigned char *dst, unsigned int val)
{
  dst[0] = (unsigned char)((val >> 24) & 0xff);
  dst[1] = (unsigned char)((val >> 16) & 0xff);
  dst[2] = (unsigned char)((val >> 8) & 0xff);
  dst[3] = (unsigned char)(val & 0xff);
}

static void build_sll2(unsigned char *dst, const struct sockaddr_ll *from)
{
  // собираем cooked v2 заголовок для pcap как у tcpdump -i any
  memset(dst, 0, SLL2_HDR_LEN);
  put_be16(dst + 0, ntohs(from->sll_protocol));
  put_be32(dst + 4, (unsigned int)from->sll_ifindex);
  put_be16(dst + 8, from->sll_hatype);
  dst[10] = from->sll_pkttype;
  dst[11] = from->sll_halen > 8 ? 8 : from->sll_halen;
  memcpy(dst + 12, from->sll_addr, dst[11]);
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

static int attach_bpf(int fd, const struct filter *f, enum bpf_link_kind link)
{
  struct sock_fprog fprog;
  struct bpf_prog prog;

  if (!f || !f->root)
    return 0;

  if (bpf_compile_link(&prog, f, link) < 0)
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
  unsigned int buf_sz;
  unsigned int hdr_len;
  unsigned short hw_type;
  struct pkt_info pi;
  struct pcap_writer pw;
  struct sockaddr_ll from;
  socklen_t fromlen;
  struct timespec ts;
  unsigned long long deadline_ms;
  unsigned long long seen;
  size_t pkt_off;
  size_t pkt_cap;
  unsigned int caplen;
  unsigned int origlen;
  ssize_t len;
  int cooked;
  int is_any;
  int ready;
  int fd;
  int rc;

  snaplen = cfg->snaplen ? cfg->snaplen : PCAP_SNAPLEN;
  is_any = !strcmp(cfg->ifname, "any");
  // any читает cooked пакеты без l2 заголовка, его дописываем сами в pcap
  cooked = is_any;
  hdr_len = is_any ? SLL2_HDR_LEN : 0;
  buf_sz = snaplen + hdr_len;

  if (is_any && cfg->filter_mode == FILTER_MODE_USER) {
    fprintf(stderr, "filter-mode user is not supported on interface any\n");
    return -1;
  }

  buf = malloc(buf_sz);
  if (!buf) {
    perror("malloc");
    return -1;
  }

  if (is_any) {
    ifindex = 0;
    linktype = PCAP_LINKTYPE_LINUX_SLL2;
  } else {
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
  }

  if (pcap_open(&pw, cfg->out_path, snaplen, linktype) < 0) {
    rc = -1;
    goto out;
  }

  fd = open_socket(ifindex, cooked);
  if (fd < 0) {
    pcap_close(&pw);
    rc = -1;
    goto out;
  }

  if (cfg->filter_mode == FILTER_MODE_BPF &&
      attach_bpf(fd, cfg->filter,
      // для any фильтр компилируется от ip payload, а не от ethernet кадра
      is_any ? BPF_LINK_IP : BPF_LINK_ETHERNET) < 0) {
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

    fromlen = sizeof(from);
    len = recvfrom(fd, buf + hdr_len, snaplen, MSG_TRUNC,
        (struct sockaddr *)&from, &fromlen);
    if (len < 0) {
      if (errno == EINTR)
        continue;
      perror("recvfrom");
      close(fd);
      pcap_close(&pw);
      rc = -1;
      goto out;
    }

    pkt_off = hdr_len;
    pkt_cap = snaplen;
    if ((size_t)len < pkt_cap)
      pkt_cap = (size_t)len;
    caplen = (unsigned int)(pkt_cap + pkt_off);
    origlen = (unsigned int)len + hdr_len;

    if (is_any)
      build_sll2(buf, &from);

    if (cfg->filter_mode == FILTER_MODE_USER &&
        cfg->filter && cfg->filter->root) {
      if (packet_parse(&pi, buf + pkt_off, (unsigned int)pkt_cap) < 0)
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

    if (pcap_write_packet(&pw, &ts, buf, caplen, origlen) < 0) {
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
