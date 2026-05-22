#ifndef UDUMP_FILTER_H
#define UDUMP_FILTER_H

enum filter_term_kind {
  TERM_TCP,
  TERM_UDP,
  TERM_PORT,
  TERM_ETHER_SRC,
  TERM_ETHER_DST,
  TERM_ETHER_HOST,
};

struct filter_term {
  enum filter_term_kind kind;
  unsigned short port;
  unsigned char mac[6];
};

struct filter {
  struct filter_term *terms;
  int nterms;
};

struct pkt_info;

int filter_parse(struct filter *f, int argc, char **argv);
int filter_match(const struct filter *f, const struct pkt_info *pi);
void filter_free(struct filter *f);

#endif
