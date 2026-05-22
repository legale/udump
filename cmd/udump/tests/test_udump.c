#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "../bpf.h"
#include "../filter.h"
#include "../packet.h"
#include "../pcap.h"

#define FIXTURE_PATH "tests/fixtures/br-eth0-30-tcp-port-22-host-172.16.133.8.pcap"

static int failures;

static void fail(const char *name, const char *msg)
{
  fprintf(stderr, "%s: %s\n", name, msg);
  failures++;
}

static unsigned int get_le32(const unsigned char *p)
{
  return (unsigned int)p[0] |
      ((unsigned int)p[1] << 8) |
      ((unsigned int)p[2] << 16) |
      ((unsigned int)p[3] << 24);
}

static int read_all(int fd, void *buf, size_t len)
{
  unsigned char *p;
  ssize_t n;

  p = buf;
  while (len) {
    n = read(fd, p, len);
    if (n < 0) {
      if (errno == EINTR)
        continue;
      return -1;
    }
    if (!n)
      return -1;
    p += n;
    len -= (size_t)n;
  }

  return 0;
}

static int next_pcap_record(FILE *fp, unsigned char *buf, size_t buf_sz,
    unsigned int *caplen)
{
  unsigned char hdr[16];
  size_t n;

  n = fread(hdr, 1, sizeof(hdr), fp);
  if (!n)
    return 0;
  if (n != sizeof(hdr))
    return -1;

  *caplen = get_le32(hdr + 8);
  if (*caplen > buf_sz)
    return -1;
  if (fread(buf, 1, *caplen, fp) != *caplen)
    return -1;

  return 1;
}

static int parse_ok(int argc, char **argv, int expect_terms)
{
  struct filter f;
  int terms;

  if (filter_parse(&f, argc, argv) < 0)
    return 0;

  terms = 0;
  if (f.root) {
    const struct filter_node *stack[64];
    int sp;

    sp = 0;
    stack[sp++] = f.root;
    while (sp) {
      const struct filter_node *node;

      node = stack[--sp];
      if (node->kind == NODE_TERM) {
        terms++;
        continue;
      }
      stack[sp++] = node->expr.rhs;
      stack[sp++] = node->expr.lhs;
    }
  }

  if (terms != expect_terms) {
    filter_free(&f);
    return 0;
  }

  filter_free(&f);
  return 1;
}

static int parse_fail(int argc, char **argv)
{
  struct filter f;
  int saved_stderr;
  int null_fd;
  int rc;

  saved_stderr = dup(STDERR_FILENO);
  if (saved_stderr < 0)
    return 0;

  null_fd = open("/dev/null", O_WRONLY);
  if (null_fd < 0) {
    close(saved_stderr);
    return 0;
  }

  if (dup2(null_fd, STDERR_FILENO) < 0) {
    close(null_fd);
    close(saved_stderr);
    return 0;
  }

  close(null_fd);
  rc = filter_parse(&f, argc, argv) < 0;
  dup2(saved_stderr, STDERR_FILENO);
  close(saved_stderr);
  return rc;
}

static void fill_pkt(struct pkt_info *pi)
{
  memset(pi, 0, sizeof(*pi));
  pi->is_ipv4 = 1;
  pi->ip_proto = 6;
  pi->has_ports = 1;
  pi->src_port = 22;
  pi->dst_port = 40000;
  pi->src_mac[0] = 0xaa;
  pi->src_mac[1] = 0xbb;
  pi->src_mac[2] = 0xcc;
  pi->src_mac[3] = 0xdd;
  pi->src_mac[4] = 0xee;
  pi->src_mac[5] = 0xff;
  pi->dst_mac[0] = 0x10;
  pi->dst_mac[1] = 0x20;
  pi->dst_mac[2] = 0x30;
  pi->dst_mac[3] = 0x40;
  pi->dst_mac[4] = 0x50;
  pi->dst_mac[5] = 0x60;
}

static int match_ok(int argc, char **argv, struct pkt_info *pi)
{
  struct filter f;
  int rc;

  if (filter_parse(&f, argc, argv) < 0)
    return 0;

  rc = filter_match(&f, pi);
  filter_free(&f);
  return rc;
}

static int match_fail(int argc, char **argv, struct pkt_info *pi)
{
  return !match_ok(argc, argv, pi);
}

static int compile_filter(struct filter *f, struct bpf_prog *prog, int argc,
    char **argv)
{
  if (filter_parse(f, argc, argv) < 0)
    return -1;
  if (bpf_compile(prog, f) < 0) {
    filter_free(f);
    return -1;
  }
  return 0;
}

static int bpf_compile_ok(int argc, char **argv)
{
  struct sock_fprog fprog;
  struct bpf_prog prog;
  struct filter f;
  int ok;

  if (compile_filter(&f, &prog, argc, argv) < 0)
    return 0;

  fprog = bpf_sock_fprog(&prog);
  ok = prog.len >= 2;
  if (ok && fprog.len != prog.len)
    ok = 0;
  if (ok && prog.insns[prog.len - 2].code != (BPF_RET | BPF_K))
    ok = 0;
  if (ok && prog.insns[prog.len - 2].k != 65535u)
    ok = 0;
  if (ok && prog.insns[prog.len - 1].code != (BPF_RET | BPF_K))
    ok = 0;
  if (ok && prog.insns[prog.len - 1].k != 0)
    ok = 0;

  bpf_prog_free(&prog);
  filter_free(&f);
  return ok;
}

static int userspace_match_raw(const struct filter *f, const void *buf,
    unsigned int len)
{
  struct pkt_info pi;

  if (packet_parse(&pi, buf, len) < 0)
    return 0;
  return filter_match(f, &pi);
}

static int kernel_match_raw(const struct bpf_prog *prog, const void *buf,
    unsigned int len, int *match)
{
  unsigned char rx[65536];
  struct sock_fprog fprog;
  struct pollfd pfd;
  int sv[2];
  ssize_t n;
  int rc;

  sv[0] = -1;
  sv[1] = -1;
  *match = 0;

  if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) < 0)
    return -1;

  fprog = bpf_sock_fprog(prog);
  if (setsockopt(sv[1], SOL_SOCKET, SO_ATTACH_FILTER,
      &fprog, sizeof(fprog)) < 0)
    goto err;

  n = send(sv[0], buf, len, 0);
  if (n != (ssize_t)len)
    goto err;

  pfd.fd = sv[1];
  pfd.events = POLLIN;
  pfd.revents = 0;

  rc = poll(&pfd, 1, 100);
  if (rc < 0)
    goto err;
  if (!rc)
    goto out;

  n = recv(sv[1], rx, sizeof(rx), 0);
  if (n < 0)
    goto err;

  *match = 1;

out:
  close(sv[0]);
  close(sv[1]);
  return 0;

err:
  if (sv[0] >= 0)
    close(sv[0]);
  if (sv[1] >= 0)
    close(sv[1]);
  return -1;
}

static int bpf_case_ok(int argc, char **argv, const unsigned char *pkt,
    unsigned int len, int expect)
{
  struct bpf_prog prog;
  struct filter f;
  int user_match;
  int kern_match;
  int ok;

  if (compile_filter(&f, &prog, argc, argv) < 0)
    return 0;

  user_match = userspace_match_raw(&f, pkt, len);
  if (kernel_match_raw(&prog, pkt, len, &kern_match) < 0) {
    bpf_prog_free(&prog);
    filter_free(&f);
    return 0;
  }

  ok = user_match == expect && kern_match == expect && user_match == kern_match;
  bpf_prog_free(&prog);
  filter_free(&f);
  return ok;
}

static void test_filter_parse(void)
{
  char *tcp[] = { "tcp" };
  char *combo[] = { "ether", "host", "aa:bb:cc:dd:ee:ff", "port", "53" };
  char *udp_ports[] = {
    "udp", "port", "67", "or", "udp", "port", "68"
  };
  char *grouped[] = {
    "(", "tcp", "or", "udp", ")", "and", "port", "53"
  };
  char *bad_tok[] = { "foo" };
  char *bad_port[] = { "port", "70000" };
  char *bad_mac[] = { "ether", "src", "aa:bb" };
  char *bad_group[] = { "(", ")" };
  char *bad_op[] = { "tcp", "or", "and", "udp" };

  if (!parse_ok(1, tcp, 1))
    fail("test_filter_parse", "tcp parse failed");
  if (!parse_ok(5, combo, 2))
    fail("test_filter_parse", "combo parse failed");
  if (!parse_ok(7, udp_ports, 4))
    fail("test_filter_parse", "udp port/or parse failed");
  if (!parse_ok(8, grouped, 3))
    fail("test_filter_parse", "grouped parse failed");
  if (!parse_fail(1, bad_tok))
    fail("test_filter_parse", "bad token accepted");
  if (!parse_fail(2, bad_port))
    fail("test_filter_parse", "bad port accepted");
  if (!parse_fail(3, bad_mac))
    fail("test_filter_parse", "bad mac accepted");
  if (!parse_fail(2, bad_group))
    fail("test_filter_parse", "empty group accepted");
  if (!parse_fail(4, bad_op))
    fail("test_filter_parse", "bad operators accepted");
}

static void test_filter_match(void)
{
  struct pkt_info pi;
  char *tcp[] = { "tcp" };
  char *udp[] = { "udp" };
  char *port22[] = { "port", "22" };
  char *port53[] = { "port", "53" };
  char *src[] = { "ether", "src", "aa:bb:cc:dd:ee:ff" };
  char *dst[] = { "ether", "dst", "10:20:30:40:50:60" };
  char *host[] = { "ether", "host", "10:20:30:40:50:60" };
  char *combo[] = { "tcp", "port", "22", "ether", "src", "aa:bb:cc:dd:ee:ff" };
  char *or_match[] = {
    "udp", "port", "53", "or", "tcp", "port", "22"
  };
  char *or_fail[] = {
    "udp", "port", "53", "or", "tcp", "port", "80"
  };
  char *left_assoc[] = {
    "tcp", "or", "udp", "and", "port", "22"
  };

  fill_pkt(&pi);

  if (!match_ok(1, tcp, &pi))
    fail("test_filter_match", "tcp did not match");
  if (!match_fail(1, udp, &pi))
    fail("test_filter_match", "udp matched");
  if (!match_ok(2, port22, &pi))
    fail("test_filter_match", "port 22 did not match");
  if (!match_fail(2, port53, &pi))
    fail("test_filter_match", "port 53 matched");
  if (!match_ok(3, src, &pi))
    fail("test_filter_match", "ether src did not match");
  if (!match_ok(3, dst, &pi))
    fail("test_filter_match", "ether dst did not match");
  if (!match_ok(3, host, &pi))
    fail("test_filter_match", "ether host did not match");
  if (!match_ok(6, combo, &pi))
    fail("test_filter_match", "combined filter did not match");
  if (!match_ok(7, or_match, &pi))
    fail("test_filter_match", "or filter did not match");
  if (!match_fail(7, or_fail, &pi))
    fail("test_filter_match", "or filter false-positive");
  if (!match_ok(6, left_assoc, &pi))
    fail("test_filter_match", "left-assoc libpcap semantics mismatch");
}

static void test_bpf_compile_ether(void)
{
  char *src[] = { "ether", "src", "aa:bb:cc:dd:ee:ff" };
  char *dst[] = { "ether", "dst", "10:20:30:40:50:60" };
  char *host[] = { "ether", "host", "10:20:30:40:50:60" };

  if (!bpf_compile_ok(3, src))
    fail("test_bpf_compile_ether", "ether src bpf compile failed");
  if (!bpf_compile_ok(3, dst))
    fail("test_bpf_compile_ether", "ether dst bpf compile failed");
  if (!bpf_compile_ok(3, host))
    fail("test_bpf_compile_ether", "ether host bpf compile failed");
}

static void test_bpf_compile_l4(void)
{
  char *tcp[] = { "tcp" };
  char *udp[] = { "udp" };
  char *port[] = { "port", "22" };
  char *combo[] = { "tcp", "port", "22" };

  if (!bpf_compile_ok(1, tcp))
    fail("test_bpf_compile_l4", "tcp bpf compile failed");
  if (!bpf_compile_ok(1, udp))
    fail("test_bpf_compile_l4", "udp bpf compile failed");
  if (!bpf_compile_ok(2, port))
    fail("test_bpf_compile_l4", "port bpf compile failed");
  if (!bpf_compile_ok(3, combo))
    fail("test_bpf_compile_l4", "tcp port bpf compile failed");
}

static void test_bpf_kernel_parity_crafted(void)
{
  unsigned char tcp_pkt[54] = {
    0x10, 0x20, 0x30, 0x40, 0x50, 0x60,
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    0x08, 0x00,
    0x45, 0x00, 0x00, 0x28,
    0x00, 0x00, 0x00, 0x00,
    0x40, 0x06, 0x00, 0x00,
    127, 0, 0, 1,
    127, 0, 0, 1,
    0x30, 0x39, 0x00, 0x16,
    0, 0, 0, 0,
    0, 0, 0, 0,
    0x50, 0x00, 0, 0,
    0, 0, 0, 0
  };
  unsigned char udp_pkt[42] = {
    0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    0x08, 0x00,
    0x45, 0x00, 0x00, 0x1c,
    0x00, 0x00, 0x00, 0x00,
    0x40, 0x11, 0x00, 0x00,
    127, 0, 0, 1,
    127, 0, 0, 1,
    0x00, 0x35, 0x1f, 0x90,
    0x00, 0x08, 0x00, 0x00
  };
  unsigned char arp_pkt[14] = {
    0x10, 0x20, 0x30, 0x40, 0x50, 0x60,
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    0x08, 0x06
  };
  unsigned char trunc_pkt[24] = {
    0x10, 0x20, 0x30, 0x40, 0x50, 0x60,
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    0x08, 0x00,
    0x45, 0x00, 0x00, 0x28,
    0x00, 0x00, 0x00, 0x00,
    0x40, 0x06
  };

  if (!bpf_case_ok(1, (char *[]){"tcp"}, tcp_pkt, sizeof(tcp_pkt), 1))
    fail("test_bpf_kernel_parity_crafted", "tcp packet mismatch");
  if (!bpf_case_ok(1, (char *[]){"udp"}, tcp_pkt, sizeof(tcp_pkt), 0))
    fail("test_bpf_kernel_parity_crafted", "tcp/udp mismatch");
  if (!bpf_case_ok(1, (char *[]){"udp"}, udp_pkt, sizeof(udp_pkt), 1))
    fail("test_bpf_kernel_parity_crafted", "udp packet mismatch");
  if (!bpf_case_ok(2, (char *[]){"port", "22"}, tcp_pkt, sizeof(tcp_pkt), 1))
    fail("test_bpf_kernel_parity_crafted", "port 22 mismatch");
  if (!bpf_case_ok(2, (char *[]){"port", "53"}, udp_pkt, sizeof(udp_pkt), 1))
    fail("test_bpf_kernel_parity_crafted", "port 53 mismatch");
  if (!bpf_case_ok(3, (char *[]){"ether", "src", "aa:bb:cc:dd:ee:ff"},
      tcp_pkt, sizeof(tcp_pkt), 1))
    fail("test_bpf_kernel_parity_crafted", "ether src mismatch");
  if (!bpf_case_ok(3, (char *[]){"ether", "dst", "10:20:30:40:50:60"},
      tcp_pkt, sizeof(tcp_pkt), 1))
    fail("test_bpf_kernel_parity_crafted", "ether dst mismatch");
  if (!bpf_case_ok(3, (char *[]){"ether", "host", "10:20:30:40:50:60"},
      tcp_pkt, sizeof(tcp_pkt), 1))
    fail("test_bpf_kernel_parity_crafted", "ether host mismatch");
  if (!bpf_case_ok(3, (char *[]){"ether", "dst", "66:55:44:33:22:11"},
      tcp_pkt, sizeof(tcp_pkt), 0))
    fail("test_bpf_kernel_parity_crafted", "ether dst negative mismatch");
  if (!bpf_case_ok(3, (char *[]){"tcp", "port", "22"},
      tcp_pkt, sizeof(tcp_pkt), 1))
    fail("test_bpf_kernel_parity_crafted", "tcp port 22 mismatch");
  if (!bpf_case_ok(1, (char *[]){"tcp"}, arp_pkt, sizeof(arp_pkt), 0))
    fail("test_bpf_kernel_parity_crafted", "arp/tcp mismatch");
  if (!bpf_case_ok(1, (char *[]){"tcp"}, trunc_pkt, sizeof(trunc_pkt), 0))
    fail("test_bpf_kernel_parity_crafted", "truncated ipv4 mismatch");
}

static void test_packet_parse(void)
{
  unsigned char pkt[54] = {
    0, 1, 2, 3, 4, 5,
    6, 7, 8, 9, 10, 11,
    0x08, 0x00,
    0x45, 0x00, 0x00, 0x28,
    0x00, 0x00, 0x00, 0x00,
    0x40, 0x06, 0x00, 0x00,
    127, 0, 0, 1,
    127, 0, 0, 1,
    0x12, 0x34, 0x00, 0x50,
    0, 0, 0, 0,
    0, 0, 0, 0,
    0x50, 0x00, 0, 0,
    0, 0, 0, 0
  };
  struct pkt_info pi;

  if (packet_parse(&pi, pkt, sizeof(pkt)) < 0) {
    fail("test_packet_parse", "valid tcp packet rejected");
    return;
  }

  if (!pi.is_ipv4 || pi.ip_proto != 6 || !pi.has_ports)
    fail("test_packet_parse", "missing parsed tcp fields");
  if (pi.src_port != 0x1234 || pi.dst_port != 0x0050)
    fail("test_packet_parse", "wrong parsed ports");
}

static void test_pcap_writer(void)
{
  struct pcap_writer pw;
  struct timespec ts;
  char path[] = "/tmp/udump-test-XXXXXX";
  unsigned char data[4] = { 1, 2, 3, 4 };
  unsigned char hdr[24];
  int fd;

  fd = mkstemp(path);
  if (fd < 0) {
    fail("test_pcap_writer", "mkstemp failed");
    return;
  }
  close(fd);

  if (pcap_open(&pw, path) < 0) {
    fail("test_pcap_writer", "pcap_open failed");
    unlink(path);
    return;
  }

  ts.tv_sec = 1;
  ts.tv_nsec = 2000;
  if (pcap_write_packet(&pw, &ts, data, sizeof(data), sizeof(data)) < 0) {
    fail("test_pcap_writer", "pcap_write_packet failed");
    pcap_close(&pw);
    unlink(path);
    return;
  }

  if (pcap_close(&pw) < 0) {
    fail("test_pcap_writer", "pcap_close failed");
    unlink(path);
    return;
  }

  fd = open(path, O_RDONLY);
  if (fd < 0) {
    fail("test_pcap_writer", "open output failed");
    unlink(path);
    return;
  }

  if (read_all(fd, hdr, sizeof(hdr)) < 0) {
    fail("test_pcap_writer", "read header failed");
    close(fd);
    unlink(path);
    return;
  }

  if (hdr[0] != 0xd4 || hdr[1] != 0xc3 || hdr[2] != 0xb2 || hdr[3] != 0xa1)
    fail("test_pcap_writer", "bad pcap magic");

  close(fd);
  unlink(path);
}

static void test_fixture_tcp_port_22(void)
{
  unsigned char buf[65536];
  struct filter f;
  struct pkt_info pi;
  unsigned int caplen;
  int matches;
  int rc;
  FILE *fp;

  fp = fopen(FIXTURE_PATH, "rb");
  if (!fp) {
    fail("test_fixture_tcp_port_22", "fixture open failed");
    return;
  }

  if (fseek(fp, 24, SEEK_SET) < 0) {
    fail("test_fixture_tcp_port_22", "fixture seek failed");
    fclose(fp);
    return;
  }

  if (filter_parse(&f, 3, (char *[]){"tcp", "port", "22"}) < 0) {
    fail("test_fixture_tcp_port_22", "filter_parse failed");
    fclose(fp);
    return;
  }

  matches = 0;
  for (;;) {
    rc = next_pcap_record(fp, buf, sizeof(buf), &caplen);
    if (rc == 0)
      break;
    if (rc < 0) {
      fail("test_fixture_tcp_port_22", "pcap record read failed");
      break;
    }
    if (packet_parse(&pi, buf, caplen) < 0)
      continue;
    if (filter_match(&f, &pi))
      matches++;
  }

  if (!matches)
    fail("test_fixture_tcp_port_22", "no tcp port 22 packets in fixture");

  filter_free(&f);
  fclose(fp);
}

static void test_bpf_fixture_parity(void)
{
  unsigned char buf[65536];
  struct bpf_prog prog;
  struct filter f;
  unsigned int caplen;
  int user_match;
  int kern_match;
  int rc;
  FILE *fp;

  fp = fopen(FIXTURE_PATH, "rb");
  if (!fp) {
    fail("test_bpf_fixture_parity", "fixture open failed");
    return;
  }

  if (fseek(fp, 24, SEEK_SET) < 0) {
    fail("test_bpf_fixture_parity", "fixture seek failed");
    fclose(fp);
    return;
  }

  if (compile_filter(&f, &prog, 3, (char *[]){"tcp", "port", "22"}) < 0) {
    fail("test_bpf_fixture_parity", "filter compile failed");
    fclose(fp);
    return;
  }

  for (;;) {
    rc = next_pcap_record(fp, buf, sizeof(buf), &caplen);
    if (rc == 0)
      break;
    if (rc < 0) {
      fail("test_bpf_fixture_parity", "pcap record read failed");
      break;
    }

    user_match = userspace_match_raw(&f, buf, caplen);
    if (kernel_match_raw(&prog, buf, caplen, &kern_match) < 0) {
      fail("test_bpf_fixture_parity", "kernel match failed");
      break;
    }

    if (user_match != kern_match) {
      fail("test_bpf_fixture_parity", "kernel/user mismatch on fixture");
      break;
    }
  }

  bpf_prog_free(&prog);
  filter_free(&f);
  fclose(fp);
}

int main(void)
{
  test_filter_parse();
  test_filter_match();
  test_bpf_compile_ether();
  test_bpf_compile_l4();
  test_bpf_kernel_parity_crafted();
  test_packet_parse();
  test_pcap_writer();
  test_fixture_tcp_port_22();
  test_bpf_fixture_parity();

  if (failures)
    return 1;
  return 0;
}
