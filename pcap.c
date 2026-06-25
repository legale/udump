#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "pcap.h"

static void put_le16(unsigned char *dst, unsigned int val)
{
  dst[0] = val & 0xff;
  dst[1] = (val >> 8) & 0xff;
}

static void put_le32(unsigned char *dst, unsigned int val)
{
  dst[0] = val & 0xff;
  dst[1] = (val >> 8) & 0xff;
  dst[2] = (val >> 16) & 0xff;
  dst[3] = (val >> 24) & 0xff;
}

static int write_all(int fd, const void *buf, size_t len)
{
  const unsigned char *p;
  ssize_t n;

  p = buf;
  while (len) {
    n = write(fd, p, len);
    if (n < 0) {
      if (errno == EINTR)
        continue;
      return -1;
    }

    p += n;
    len -= (size_t)n;
  }

  return 0;
}

int pcap_open(struct pcap_writer *pw, const char *path)
{
  unsigned char hdr[24];

  if (!strcmp(path, "-"))
    pw->fd = dup(STDOUT_FILENO);
  else
    pw->fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
  if (pw->fd < 0) {
    if (!strcmp(path, "-"))
      perror("dup");
    else
      perror(path);
    return -1;
  }

  put_le32(hdr + 0, 0xa1b2c3d4u);
  put_le16(hdr + 4, 2);
  put_le16(hdr + 6, 4);
  put_le32(hdr + 8, 0);
  put_le32(hdr + 12, 0);
  put_le32(hdr + 16, 65535u);
  put_le32(hdr + 20, 1u);

  if (write_all(pw->fd, hdr, sizeof(hdr)) < 0) {
    perror("write");
    close(pw->fd);
    pw->fd = -1;
    return -1;
  }

  return 0;
}

int pcap_write_packet(struct pcap_writer *pw, const struct timespec *ts,
    const void *buf, unsigned int caplen, unsigned int origlen)
{
  unsigned char hdr[16];

  put_le32(hdr + 0, (unsigned int)ts->tv_sec);
  put_le32(hdr + 4, (unsigned int)(ts->tv_nsec / 1000));
  put_le32(hdr + 8, caplen);
  put_le32(hdr + 12, origlen);

  if (write_all(pw->fd, hdr, sizeof(hdr)) < 0) {
    perror("write");
    return -1;
  }

  if (write_all(pw->fd, buf, caplen) < 0) {
    perror("write");
    return -1;
  }

  return 0;
}

int pcap_close(struct pcap_writer *pw)
{
  if (close(pw->fd) < 0) {
    perror("close");
    return -1;
  }

  pw->fd = -1;
  return 0;
}
