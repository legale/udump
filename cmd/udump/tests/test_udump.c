#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

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

  if (filter_parse(&f, argc, argv) < 0)
    return 0;
  if (f.nterms != expect_terms) {
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

static void test_filter_parse(void)
{
  char *tcp[] = { "tcp" };
  char *combo[] = { "ether", "host", "aa:bb:cc:dd:ee:ff", "port", "53" };
  char *bad_tok[] = { "foo" };
  char *bad_port[] = { "port", "70000" };
  char *bad_mac[] = { "ether", "src", "aa:bb" };

  if (!parse_ok(1, tcp, 1))
    fail("test_filter_parse", "tcp parse failed");
  if (!parse_ok(5, combo, 2))
    fail("test_filter_parse", "combo parse failed");
  if (!parse_fail(1, bad_tok))
    fail("test_filter_parse", "bad token accepted");
  if (!parse_fail(2, bad_port))
    fail("test_filter_parse", "bad port accepted");
  if (!parse_fail(3, bad_mac))
    fail("test_filter_parse", "bad mac accepted");
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

int main(void)
{
  test_filter_parse();
  test_filter_match();
  test_packet_parse();
  test_pcap_writer();
  test_fixture_tcp_port_22();

  if (failures)
    return 1;
  return 0;
}
