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
  unsigned short port_hi;
  unsigned char mac[6];
  unsigned char has_port_hi;
  unsigned char l4_proto;
};

enum filter_node_kind {
  NODE_TERM,
  NODE_AND,
  NODE_OR,
};

struct filter_node {
  enum filter_node_kind kind;
  union {
    struct filter_term term;
    struct {
      struct filter_node *lhs;
      struct filter_node *rhs;
    } expr;
  };
};

struct filter {
  struct filter_node *root;
};

struct pkt_info;

int filter_parse(struct filter *f, int argc, char **argv);
int filter_match(const struct filter *f, const struct pkt_info *pi);
int filter_normalize(struct filter *dst, const struct filter *src);
void filter_free(struct filter *f);

#endif
