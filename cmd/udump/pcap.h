#ifndef UDUMP_PCAP_H
#define UDUMP_PCAP_H

#include <time.h>

struct pcap_writer {
  int fd;
};

int pcap_open(struct pcap_writer *pw, const char *path);
int pcap_write_packet(struct pcap_writer *pw, const struct timespec *ts,
    const void *buf, unsigned int caplen, unsigned int origlen);
int pcap_close(struct pcap_writer *pw);

#endif
