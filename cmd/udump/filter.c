#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "filter.h"
#include "packet.h"

static int hex_digit(int ch)
{
  if (ch >= '0' && ch <= '9')
    return ch - '0';
  if (ch >= 'a' && ch <= 'f')
    return ch - 'a' + 10;
  if (ch >= 'A' && ch <= 'F')
    return ch - 'A' + 10;
  return -1;
}

static int parse_mac(const char *arg, unsigned char *mac)
{
  int hi;
  int lo;
  int i;

  for (i = 0; i < 6; i++) {
    hi = hex_digit(arg[0]);
    lo = hex_digit(arg[1]);
    if (hi < 0 || lo < 0)
      return -1;
    mac[i] = (unsigned char)((hi << 4) | lo);
    arg += 2;

    if (i == 5)
      break;
    if (*arg != ':')
      return -1;
    arg++;
  }

  return *arg ? -1 : 0;
}

static int parse_port(const char *arg, unsigned short *port)
{
  char *end;
  unsigned long val;

  errno = 0;
  val = strtoul(arg, &end, 10);
  if (errno || *arg == '\0' || *end != '\0' || val > 65535) {
    fprintf(stderr, "invalid port: %s\n", arg);
    return -1;
  }

  *port = (unsigned short)val;
  return 0;
}

static int need_more(const char *what)
{
  fprintf(stderr, "missing %s\n", what);
  return -1;
}

static struct filter_node *node_alloc(void)
{
  struct filter_node *node;

  node = calloc(1, sizeof(*node));
  if (!node)
    perror("calloc");
  return node;
}

static struct filter_node *node_term(enum filter_term_kind kind)
{
  struct filter_node *node;

  node = node_alloc();
  if (!node)
    return NULL;

  node->kind = NODE_TERM;
  node->term.kind = kind;
  return node;
}

static struct filter_node *node_and(struct filter_node *lhs,
    struct filter_node *rhs)
{
  struct filter_node *node;

  node = node_alloc();
  if (!node)
    return NULL;

  node->kind = NODE_AND;
  node->expr.lhs = lhs;
  node->expr.rhs = rhs;
  return node;
}

static void filter_free_node(struct filter_node *node)
{
  if (!node)
    return;

  if (node->kind == NODE_AND || node->kind == NODE_OR) {
    filter_free_node(node->expr.lhs);
    filter_free_node(node->expr.rhs);
  }

  free(node);
}

static struct filter_node *parse_atom(int argc, char **argv, int *used)
{
  struct filter_node *node;

  if (!argc)
    return NULL;

  *used = 0;

  if (!strcmp(argv[0], "tcp")) {
    *used = 1;
    return node_term(TERM_TCP);
  }

  if (!strcmp(argv[0], "udp")) {
    *used = 1;
    return node_term(TERM_UDP);
  }

  if (!strcmp(argv[0], "port")) {
    if (argc < 2) {
      need_more("port value");
      return NULL;
    }

    node = node_term(TERM_PORT);
    if (!node)
      return NULL;

    if (parse_port(argv[1], &node->term.port) < 0) {
      free(node);
      return NULL;
    }

    *used = 2;
    return node;
  }

  if (!strcmp(argv[0], "ether")) {
    if (argc < 3) {
      need_more("ether filter");
      return NULL;
    }

    if (!strcmp(argv[1], "src"))
      node = node_term(TERM_ETHER_SRC);
    else if (!strcmp(argv[1], "dst"))
      node = node_term(TERM_ETHER_DST);
    else if (!strcmp(argv[1], "host"))
      node = node_term(TERM_ETHER_HOST);
    else {
      fprintf(stderr, "unsupported ether qualifier: %s\n", argv[1]);
      return NULL;
    }
    if (!node)
      return NULL;

    if (parse_mac(argv[2], node->term.mac) < 0) {
      fprintf(stderr, "invalid mac: %s\n", argv[2]);
      free(node);
      return NULL;
    }

    *used = 3;
    return node;
  }

  fprintf(stderr, "unsupported filter token: %s\n", argv[0]);
  return NULL;
}

int filter_parse(struct filter *f, int argc, char **argv)
{
  struct filter_node *node;
  struct filter_node *root;
  int used;
  int i;

  memset(f, 0, sizeof(*f));

  if (!argc)
    return 0;

  root = NULL;
  i = 0;
  while (i < argc) {
    node = parse_atom(argc - i, argv + i, &used);
    if (!node)
      goto err;

    if (!root) {
      root = node;
    } else {
      root = node_and(root, node);
      if (!root) {
        filter_free_node(node);
        goto err;
      }
    }

    i += used;
  }

  f->root = root;
  return 0;

err:
  filter_free(f);
  return -1;
}

static int filter_match_node(const struct filter_node *node,
    const struct pkt_info *pi)
{
  const struct filter_term *term;

  if (!node)
    return 1;

  switch (node->kind) {
  case NODE_TERM:
    term = &node->term;
    switch (term->kind) {
    case TERM_TCP:
      return pi->is_ipv4 && pi->ip_proto == 6;
    case TERM_UDP:
      return pi->is_ipv4 && pi->ip_proto == 17;
    case TERM_PORT:
      if (!pi->has_ports)
        return 0;
      return pi->src_port == term->port || pi->dst_port == term->port;
    case TERM_ETHER_SRC:
      return !memcmp(pi->src_mac, term->mac, 6);
    case TERM_ETHER_DST:
      return !memcmp(pi->dst_mac, term->mac, 6);
    case TERM_ETHER_HOST:
      return !memcmp(pi->src_mac, term->mac, 6) ||
          !memcmp(pi->dst_mac, term->mac, 6);
    }
    return 0;
  case NODE_AND:
    if (!filter_match_node(node->expr.lhs, pi))
      return 0;
    return filter_match_node(node->expr.rhs, pi);
  case NODE_OR:
    if (filter_match_node(node->expr.lhs, pi))
      return 1;
    return filter_match_node(node->expr.rhs, pi);
  }

  return 0;
}

int filter_match(const struct filter *f, const struct pkt_info *pi)
{
  return filter_match_node(f->root, pi);
}

void filter_free(struct filter *f)
{
  filter_free_node(f->root);
  f->root = NULL;
}
