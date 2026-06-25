#include <arpa/inet.h>
#include <ctype.h>
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

static int parse_ip(const char *arg, unsigned char *ip, unsigned char *len)
{
  struct in_addr a4;
  struct in6_addr a6;

  if (inet_pton(AF_INET, arg, &a4) == 1) {
    memcpy(ip, &a4, sizeof(a4));
    *len = sizeof(a4);
    return 0;
  }

  if (inet_pton(AF_INET6, arg, &a6) == 1) {
    memcpy(ip, &a6, sizeof(a6));
    *len = sizeof(a6);
    return 0;
  }

  fprintf(stderr, "invalid ip: %s\n", arg);
  return -1;
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

static struct filter_node *node_term_copy(const struct filter_term *term)
{
  struct filter_node *node;

  node = node_term(term->kind);
  if (!node)
    return NULL;

  node->term = *term;
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

static struct filter_node *node_or(struct filter_node *lhs,
    struct filter_node *rhs)
{
  struct filter_node *node;

  node = node_alloc();
  if (!node)
    return NULL;

  node->kind = NODE_OR;
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

struct parser {
  int argc;
  char **argv;
  int pos;
};

struct tokens {
  char **argv;
  int argc;
  int cap;
};

static void tokens_free(struct tokens *toks)
{
  int i;

  for (i = 0; i < toks->argc; i++)
    free(toks->argv[i]);
  free(toks->argv);
  memset(toks, 0, sizeof(*toks));
}

static int tokens_add(struct tokens *toks, const char *str, size_t len)
{
  char **argv;
  char *tok;
  int cap;

  if (toks->argc == toks->cap) {
    cap = toks->cap ? toks->cap * 2 : 16;
    argv = realloc(toks->argv, (size_t)cap * sizeof(*argv));
    if (!argv) {
      perror("realloc");
      return -1;
    }
    toks->argv = argv;
    toks->cap = cap;
  }

  tok = malloc(len + 1);
  if (!tok) {
    perror("malloc");
    return -1;
  }
  memcpy(tok, str, len);
  tok[len] = '\0';
  toks->argv[toks->argc++] = tok;
  return 0;
}

static int filter_tokenize(struct tokens *toks, int argc, char **argv)
{
  const char *start;
  const char *p;
  int i;

  memset(toks, 0, sizeof(*toks));
  for (i = 0; i < argc; i++) {
    p = argv[i];
    while (*p) {
      while (isspace((unsigned char)*p))
        p++;
      if (!*p)
        break;

      if (*p == '(' || *p == ')') {
        if (tokens_add(toks, p, 1) < 0)
          goto err;
        p++;
        continue;
      }

      start = p;
      while (*p && !isspace((unsigned char)*p) && *p != '(' && *p != ')')
        p++;
      if (tokens_add(toks, start, (size_t)(p - start)) < 0)
        goto err;
    }
  }

  return 0;

err:
  tokens_free(toks);
  return -1;
}

static int parser_eof(const struct parser *ps)
{
  return ps->pos >= ps->argc;
}

static const char *parser_peek(const struct parser *ps)
{
  if (parser_eof(ps))
    return NULL;
  return ps->argv[ps->pos];
}

static const char *parser_next(struct parser *ps)
{
  const char *tok;

  tok = parser_peek(ps);
  if (tok)
    ps->pos++;
  return tok;
}

static int is_term_start(const char *tok)
{
  if (!tok)
    return 0;
  if (!strcmp(tok, "("))
    return 1;
  if (!strcmp(tok, "tcp"))
    return 1;
  if (!strcmp(tok, "udp"))
    return 1;
  if (!strcmp(tok, "port"))
    return 1;
  if (!strcmp(tok, "host"))
    return 1;
  if (!strcmp(tok, "src"))
    return 1;
  if (!strcmp(tok, "dst"))
    return 1;
  if (!strcmp(tok, "ether"))
    return 1;
  return 0;
}

static int is_expr_end(const char *tok)
{
  if (!tok)
    return 1;
  return !strcmp(tok, ")");
}

static struct filter_node *parse_expr(struct parser *ps);

static struct filter_node *parse_port_atom(struct parser *ps)
{
  struct filter_node *node;
  const char *tok;

  tok = parser_next(ps);
  if (!tok || strcmp(tok, "port")) {
    fprintf(stderr, "internal parser error near port\n");
    return NULL;
  }

  tok = parser_next(ps);
  if (!tok) {
    need_more("port value");
    return NULL;
  }

  node = node_term(TERM_PORT);
  if (!node)
    return NULL;

  if (parse_port(tok, &node->term.port) < 0) {
    free(node);
    return NULL;
  }

  return node;
}

static struct filter_node *parse_ether_atom(struct parser *ps)
{
  struct filter_node *node;
  const char *qual;
  const char *addr;

  parser_next(ps);
  qual = parser_next(ps);
  addr = parser_next(ps);
  if (!qual || !addr) {
    need_more("ether filter");
    return NULL;
  }

  if (!strcmp(qual, "src"))
    node = node_term(TERM_ETHER_SRC);
  else if (!strcmp(qual, "dst"))
    node = node_term(TERM_ETHER_DST);
  else if (!strcmp(qual, "host"))
    node = node_term(TERM_ETHER_HOST);
  else {
    fprintf(stderr, "unsupported ether qualifier: %s\n", qual);
    return NULL;
  }
  if (!node)
    return NULL;

  if (parse_mac(addr, node->term.mac) < 0) {
    fprintf(stderr, "invalid mac: %s\n", addr);
    free(node);
    return NULL;
  }

  return node;
}

static struct filter_node *parse_host_atom(struct parser *ps,
    enum filter_host_dir dir)
{
  struct filter_node *node;
  const char *tok;

  tok = parser_next(ps);
  if (!tok || strcmp(tok, "host")) {
    fprintf(stderr, "internal parser error near host\n");
    return NULL;
  }

  tok = parser_next(ps);
  if (!tok) {
    need_more("host address");
    return NULL;
  }

  node = node_term(TERM_HOST);
  if (!node)
    return NULL;

  node->term.ip_dir = (unsigned char)dir;
  if (parse_ip(tok, node->term.ip, &node->term.ip_len) < 0) {
    free(node);
    return NULL;
  }

  return node;
}

static struct filter_node *parse_proto_atom(struct parser *ps, const char *tok)
{
  struct filter_node *proto;
  struct filter_node *port;
  struct filter_node *node;
  const char *next;

  parser_next(ps);

  if (!strcmp(tok, "tcp"))
    proto = node_term(TERM_TCP);
  else
    proto = node_term(TERM_UDP);
  if (!proto)
    return NULL;

  next = parser_peek(ps);
  if (!next || strcmp(next, "port"))
    return proto;

  port = parse_port_atom(ps);
  if (!port) {
    free(proto);
    return NULL;
  }

  node = node_and(proto, port);
  if (!node) {
    filter_free_node(proto);
    filter_free_node(port);
  }
  return node;
}

static struct filter_node *parse_term(struct parser *ps)
{
  const char *tok;
  struct filter_node *node;

  tok = parser_peek(ps);
  if (!tok) {
    fprintf(stderr, "missing filter term\n");
    return NULL;
  }

  if (!strcmp(tok, "(")) {
    parser_next(ps);
    tok = parser_peek(ps);
    if (tok && !strcmp(tok, ")")) {
      fprintf(stderr, "empty filter group\n");
      return NULL;
    }

    node = parse_expr(ps);
    if (!node)
      return NULL;

    tok = parser_next(ps);
    if (!tok || strcmp(tok, ")")) {
      fprintf(stderr, "missing closing ')'\n");
      filter_free_node(node);
      return NULL;
    }

    return node;
  }

  if (!strcmp(tok, "tcp") || !strcmp(tok, "udp"))
    return parse_proto_atom(ps, tok);
  if (!strcmp(tok, "port"))
    return parse_port_atom(ps);
  if (!strcmp(tok, "host"))
    return parse_host_atom(ps, HOST_DIR_ANY);
  if (!strcmp(tok, "src")) {
    parser_next(ps);
    if (!parser_peek(ps) || strcmp(parser_peek(ps), "host")) {
      fprintf(stderr, "unexpected token: src\n");
      return NULL;
    }
    return parse_host_atom(ps, HOST_DIR_SRC);
  }
  if (!strcmp(tok, "dst")) {
    parser_next(ps);
    if (!parser_peek(ps) || strcmp(parser_peek(ps), "host")) {
      fprintf(stderr, "unexpected token: dst\n");
      return NULL;
    }
    return parse_host_atom(ps, HOST_DIR_DST);
  }
  if (!strcmp(tok, "ether"))
    return parse_ether_atom(ps);
  if (!strcmp(tok, "and") || !strcmp(tok, "or") || !strcmp(tok, ")")) {
    fprintf(stderr, "unexpected operator: %s\n", tok);
    return NULL;
  }

  fprintf(stderr, "unsupported filter token: %s\n", tok);
  return NULL;
}

static struct filter_node *merge_expr(enum filter_node_kind kind,
    struct filter_node *lhs, struct filter_node *rhs)
{
  if (kind == NODE_AND)
    return node_and(lhs, rhs);
  return node_or(lhs, rhs);
}

static int node_eq(const struct filter_node *lhs, const struct filter_node *rhs)
{
  if (lhs->kind != rhs->kind)
    return 0;

  if (lhs->kind == NODE_TERM)
    return !memcmp(&lhs->term, &rhs->term, sizeof(lhs->term));

  return node_eq(lhs->expr.lhs, rhs->expr.lhs) &&
      node_eq(lhs->expr.rhs, rhs->expr.rhs);
}

static int collect_ports(const struct filter_term *term, unsigned short *ports,
    int *nports)
{
  if (term->kind != TERM_PORT)
    return -1;

  ports[0] = term->port;
  *nports = 1;

  if (term->has_port_hi) {
    if (term->port_hi == term->port)
      return 0;
    ports[1] = term->port_hi;
    *nports = 2;
  }

  return 0;
}

static struct filter_node *normalize_merge_ports(const struct filter_node *lhs,
    const struct filter_node *rhs)
{
  struct filter_term term;
  unsigned short ports[2];
  unsigned short rports[2];
  int nports;
  int nrports;
  int i;
  int j;
  int seen;

  if (lhs->kind != NODE_TERM || rhs->kind != NODE_TERM)
    return NULL;
  if (lhs->term.kind != TERM_PORT || rhs->term.kind != TERM_PORT)
    return NULL;
  if (lhs->term.l4_proto != rhs->term.l4_proto)
    return NULL;
  if (collect_ports(&lhs->term, ports, &nports) < 0)
    return NULL;
  if (collect_ports(&rhs->term, rports, &nrports) < 0)
    return NULL;

  for (i = 0; i < nrports; i++) {
    seen = 0;
    for (j = 0; j < nports; j++) {
      if (ports[j] == rports[i]) {
        seen = 1;
        break;
      }
    }
    if (seen)
      continue;
    if (nports >= 2)
      return NULL;
    ports[nports++] = rports[i];
  }

  term = lhs->term;
  if (nports == 2 && ports[0] > ports[1]) {
    unsigned short tmp;

    tmp = ports[0];
    ports[0] = ports[1];
    ports[1] = tmp;
  }
  term.port = ports[0];
  term.has_port_hi = nports == 2;
  term.port_hi = nports == 2 ? ports[1] : 0;
  return node_term_copy(&term);
}

static struct filter_node *normalize_proto_port(const struct filter_node *lhs,
    const struct filter_node *rhs)
{
  struct filter_term term;

  if (lhs->kind != NODE_TERM || rhs->kind != NODE_TERM)
    return NULL;
  if (rhs->term.kind != TERM_PORT || rhs->term.l4_proto)
    return NULL;

  term = rhs->term;
  if (lhs->term.kind == TERM_TCP)
    term.l4_proto = 6;
  else if (lhs->term.kind == TERM_UDP)
    term.l4_proto = 17;
  else
    return NULL;

  return node_term_copy(&term);
}

static struct filter_node *filter_normalize_node(const struct filter_node *node)
{
  struct filter_node *lhs;
  struct filter_node *rhs;
  struct filter_node *out;

  if (node->kind == NODE_TERM)
    return node_term_copy(&node->term);

  lhs = filter_normalize_node(node->expr.lhs);
  if (!lhs)
    return NULL;
  rhs = filter_normalize_node(node->expr.rhs);
  if (!rhs) {
    filter_free_node(lhs);
    return NULL;
  }

  if (node->kind == NODE_AND) {
    out = normalize_proto_port(lhs, rhs);
    if (!out)
      out = normalize_proto_port(rhs, lhs);
    if (out) {
      filter_free_node(lhs);
      filter_free_node(rhs);
      return out;
    }
  }

  if (node_eq(lhs, rhs)) {
    filter_free_node(rhs);
    return lhs;
  }

  if (node->kind == NODE_OR) {
    out = normalize_merge_ports(lhs, rhs);
    if (out) {
      filter_free_node(lhs);
      filter_free_node(rhs);
      return out;
    }
  }

  out = merge_expr(node->kind, lhs, rhs);
  if (!out) {
    filter_free_node(lhs);
    filter_free_node(rhs);
  }
  return out;
}

static struct filter_node *parse_expr(struct parser *ps)
{
  struct filter_node *lhs;
  struct filter_node *rhs;
  struct filter_node *node;
  const char *tok;
  enum filter_node_kind kind;

  lhs = parse_term(ps);
  if (!lhs)
    return NULL;

  while (!is_expr_end(parser_peek(ps))) {
    tok = parser_peek(ps);
    if (!strcmp(tok, "and")) {
      kind = NODE_AND;
      parser_next(ps);
    } else if (!strcmp(tok, "or")) {
      kind = NODE_OR;
      parser_next(ps);
    } else if (is_term_start(tok)) {
      kind = NODE_AND;
    } else {
      fprintf(stderr, "unexpected token: %s\n", tok);
      filter_free_node(lhs);
      return NULL;
    }

    rhs = parse_term(ps);
    if (!rhs) {
      filter_free_node(lhs);
      return NULL;
    }

    node = merge_expr(kind, lhs, rhs);
    if (!node) {
      filter_free_node(lhs);
      filter_free_node(rhs);
      return NULL;
    }
    lhs = node;
  }

  return lhs;
}

int filter_parse(struct filter *f, int argc, char **argv)
{
  struct tokens toks;
  struct parser ps;

  memset(f, 0, sizeof(*f));
  if (!argc)
    return 0;

  if (filter_tokenize(&toks, argc, argv) < 0)
    return -1;
  if (!toks.argc) {
    tokens_free(&toks);
    return 0;
  }

  ps.argc = toks.argc;
  ps.argv = toks.argv;
  ps.pos = 0;

  f->root = parse_expr(&ps);
  if (!f->root)
    goto err;

  if (!parser_eof(&ps)) {
    fprintf(stderr, "unexpected token: %s\n", parser_peek(&ps));
    goto err;
  }

  tokens_free(&toks);
  return 0;

err:
  filter_free(f);
  tokens_free(&toks);
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
      return (pi->is_ipv4 || pi->is_ipv6) && pi->ip_proto == 6;
    case TERM_UDP:
      return (pi->is_ipv4 || pi->is_ipv6) && pi->ip_proto == 17;
    case TERM_PORT:
      if (!pi->has_ports)
        return 0;
      if (term->l4_proto && pi->ip_proto != term->l4_proto)
        return 0;
      if (pi->src_port == term->port || pi->dst_port == term->port)
        return 1;
      if (term->has_port_hi &&
          (pi->src_port == term->port_hi || pi->dst_port == term->port_hi))
        return 1;
      return 0;
    case TERM_HOST:
      if (term->ip_len == 4) {
        if (!pi->is_ipv4)
          return 0;
        if (term->ip_dir != HOST_DIR_DST && pi->src_ip_len == 4 &&
            !memcmp(pi->src_ip, term->ip, 4))
          return 1;
        if (term->ip_dir != HOST_DIR_SRC && pi->dst_ip_len == 4 &&
            !memcmp(pi->dst_ip, term->ip, 4))
          return 1;
        return 0;
      } else if (term->ip_len == 16) {
        if (!pi->is_ipv6)
          return 0;
        if (term->ip_dir != HOST_DIR_DST && pi->src_ip_len == 16 &&
            !memcmp(pi->src_ip, term->ip, 16))
          return 1;
        if (term->ip_dir != HOST_DIR_SRC && pi->dst_ip_len == 16 &&
            !memcmp(pi->dst_ip, term->ip, 16))
          return 1;
        return 0;
      } else {
        return 0;
      }
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

int filter_normalize(struct filter *dst, const struct filter *src)
{
  memset(dst, 0, sizeof(*dst));
  if (!src->root)
    return 0;

  dst->root = filter_normalize_node(src->root);
  if (!dst->root)
    return -1;
  return 0;
}

void filter_free(struct filter *f)
{
  filter_free_node(f->root);
  f->root = NULL;
}
