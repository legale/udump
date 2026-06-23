#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "bpf.h"
#include "capture.h"
#include "filter.h"
#include "packet.h"
#include "pcap.h"

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

static int open_socket(const char *ifname)
{
  struct sockaddr_ll sll;
  unsigned int ifindex;
  int fd;

  ifindex = if_nametoindex(ifname);
  if (!ifindex) {
    fprintf(stderr, "unknown interface: %s\n", ifname);
    return -1;
  }

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
  unsigned char buf[65536];
  struct pkt_info pi;
  struct pcap_writer pw;
  struct timespec ts;
  unsigned long long deadline_ms;
  unsigned long long seen;
  ssize_t len;
  int ready;
  int fd;

  if (pcap_open(&pw, cfg->out_path) < 0)
    return -1;

  fd = open_socket(cfg->ifname);
  if (fd < 0) {
    pcap_close(&pw);
    return -1;
  }

  if (cfg->filter_mode == FILTER_MODE_BPF &&
      attach_bpf(fd, cfg->filter) < 0) {
    close(fd);
    pcap_close(&pw);
    return -1;
  }

  deadline_ms = 0;
  if (cfg->time_limit) {
    if (now_ms(&deadline_ms) < 0) {
      close(fd);
      pcap_close(&pw);
      return -1;
    }
    deadline_ms += (unsigned long long)cfg->time_limit * 1000ull;
  }

  seen = 0;
  for (;;) {
    ready = wait_packet(fd, deadline_ms);
    if (ready < 0) {
      close(fd);
      pcap_close(&pw);
      return -1;
    }

    if (!ready)
      break;

    len = recvfrom(fd, buf, sizeof(buf), 0, NULL, NULL);
    if (len < 0) {
      if (errno == EINTR)
        continue;
      perror("recvfrom");
      close(fd);
      pcap_close(&pw);
      return -1;
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
      return -1;
    }

    if (pcap_write_packet(&pw, &ts, buf, (unsigned int)len,
        (unsigned int)len) < 0) {
      close(fd);
      pcap_close(&pw);
      return -1;
    }

    seen++;
    if (cfg->pkt_limit && seen >= cfg->pkt_limit)
      break;
  }

  if (close(fd) < 0) {
    perror("close");
    pcap_close(&pw);
    return -1;
  }

  if (pcap_close(&pw) < 0)
    return -1;

  return 0;
}
