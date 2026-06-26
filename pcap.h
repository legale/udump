#ifndef UDUMP_PCAP_H
#define UDUMP_PCAP_H

#include <time.h>

#define PCAP_SNAPLEN 262144u
#define PCAP_LINKTYPE_EN10MB 1u
#define PCAP_LINKTYPE_IEEE802_11 105u
#define PCAP_LINKTYPE_PRISM_HEADER 119u
#define PCAP_LINKTYPE_IEEE802_11_RADIO 127u
#define PCAP_LINKTYPE_LINUX_SLL2 276u

struct pcap_writer {
  int fd;
};

int pcap_open(struct pcap_writer *pw, const char *path, unsigned int snaplen,
    unsigned int linktype);
int pcap_write_packet(struct pcap_writer *pw, const struct timespec *ts,
    const void *buf, unsigned int caplen, unsigned int origlen);
int pcap_close(struct pcap_writer *pw);

#endif
