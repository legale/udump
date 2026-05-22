#include <string.h>

#include "packet.h"

static unsigned short get_be16(const unsigned char *p)
{
  return (unsigned short)((p[0] << 8) | p[1]);
}

int packet_parse(struct pkt_info *pi, const void *buf, unsigned int len)
{
  const unsigned char *p;
  unsigned int ip_len;
  unsigned int ip_off;
  unsigned int frag_off;
  unsigned int l4_off;
  unsigned int payload_len;
  unsigned int version;
  unsigned int ihl;

  memset(pi, 0, sizeof(*pi));

  if (len < 14)
    return -1;

  p = buf;
  memcpy(pi->dst_mac, p + 0, 6);
  memcpy(pi->src_mac, p + 6, 6);
  pi->ether_type = get_be16(p + 12);

  if (pi->ether_type != 0x0800)
    goto maybe_ipv6;

  if (len < 15)
    return -1;

  p += 14;
  version = p[0] >> 4;
  ihl = (p[0] & 0x0f) * 4;
  if (version != 4 || ihl < 20)
    return -1;

  pi->is_ipv4 = 1;
  if (len >= 24)
    pi->ip_proto = p[9];
  else
    return 0;

  if (len < 18)
    return 0;

  ip_len = get_be16(p + 2);
  if (ip_len < ihl)
    return -1;
  if (len < 14 + ihl)
    return 0;

  if (len < 22)
    return 0;
  frag_off = get_be16(p + 6);
  if (frag_off & 0x1fff)
    return 0;

  l4_off = 14 + ihl;
  ip_off = ihl;
  if (len < l4_off + 4)
    return 0;
  if ((pi->ip_proto == 6 || pi->ip_proto == 17) && ip_len >= ip_off + 4) {
    pi->src_port = get_be16((const unsigned char *)buf + l4_off + 0);
    pi->dst_port = get_be16((const unsigned char *)buf + l4_off + 2);
    pi->has_ports = 1;
  }

  return 0;

maybe_ipv6:
  if (pi->ether_type != 0x86dd)
    return 0;

  if (len < 15)
    return -1;

  p = (const unsigned char *)buf + 14;
  version = p[0] >> 4;
  if (version != 6)
    return -1;

  pi->is_ipv6 = 1;
  if (len >= 21)
    pi->ip_proto = p[6];
  else
    return 0;

  if (len < 54)
    return 0;

  payload_len = get_be16(p + 4);
  if ((pi->ip_proto == 6 || pi->ip_proto == 17) && payload_len >= 4) {
    if (len < 58)
      return 0;
    pi->src_port = get_be16((const unsigned char *)buf + 54);
    pi->dst_port = get_be16((const unsigned char *)buf + 56);
    pi->has_ports = 1;
  }

  return 0;
}
