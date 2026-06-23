#ifndef UDUMP_PACKET_H
#define UDUMP_PACKET_H

struct pkt_info {
  unsigned char src_mac[6];
  unsigned char dst_mac[6];
  unsigned char src_ip[16];
  unsigned char dst_ip[16];
  unsigned char src_ip_len;
  unsigned char dst_ip_len;
  unsigned short ether_type;
  unsigned short src_port;
  unsigned short dst_port;
  unsigned char is_ipv4;
  unsigned char is_ipv6;
  unsigned char ip_proto;
  unsigned char has_ports;
};

int packet_parse(struct pkt_info *pi, const void *buf, unsigned int len);

#endif
