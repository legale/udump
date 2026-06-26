#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

#include "bpf.h"
#include "cli.h"
#include "capture.h"
#include "filter.h"

static void dump_indent(FILE *out, int depth)
{
  while (depth-- > 0)
    fputs("  ", out);
}

static void dump_term(FILE *out, const struct filter_term *term)
{
  char ip[INET6_ADDRSTRLEN];

  switch (term->kind) {
  case TERM_TCP:
    fputs("tcp", out);
    return;
  case TERM_UDP:
    fputs("udp", out);
    return;
  case TERM_HOST:
    if (term->ip_len == 4)
      inet_ntop(AF_INET, term->ip, ip, sizeof(ip));
    else if (term->ip_len == 16)
      inet_ntop(AF_INET6, term->ip, ip, sizeof(ip));
    else
      strcpy(ip, "<bad>");
    if (term->ip_dir == HOST_DIR_SRC)
      fprintf(out, "src host %s", ip);
    else if (term->ip_dir == HOST_DIR_DST)
      fprintf(out, "dst host %s", ip);
    else
      fprintf(out, "host %s", ip);
    return;
  case TERM_PORT:
    if (term->l4_proto == 6)
      fputs("tcp ", out);
    else if (term->l4_proto == 17)
      fputs("udp ", out);
    fprintf(out, "port %u", term->port);
    if (term->has_port_hi)
      fprintf(out, " or %u", term->port_hi);
    return;
  case TERM_ETHER_SRC:
    fprintf(out, "ether src %02x:%02x:%02x:%02x:%02x:%02x",
        term->mac[0], term->mac[1], term->mac[2],
        term->mac[3], term->mac[4], term->mac[5]);
    return;
  case TERM_ETHER_DST:
    fprintf(out, "ether dst %02x:%02x:%02x:%02x:%02x:%02x",
        term->mac[0], term->mac[1], term->mac[2],
        term->mac[3], term->mac[4], term->mac[5]);
    return;
  case TERM_ETHER_HOST:
    fprintf(out, "ether host %02x:%02x:%02x:%02x:%02x:%02x",
        term->mac[0], term->mac[1], term->mac[2],
        term->mac[3], term->mac[4], term->mac[5]);
    return;
  }
}

static void dump_ast(FILE *out, const struct filter_node *node, int depth)
{
  if (!node) {
    dump_indent(out, depth);
    fputs("<empty>\n", out);
    return;
  }

  dump_indent(out, depth);
  if (node->kind == NODE_TERM) {
    dump_term(out, &node->term);
    fputc('\n', out);
    return;
  }

  if (node->kind == NODE_NOT) {
    fputs("not\n", out);
    dump_ast(out, node->child, depth + 1);
    return;
  }

  if (node->kind == NODE_AND)
    fputs("and\n", out);
  else
    fputs("or\n", out);

  dump_ast(out, node->expr.lhs, depth + 1);
  dump_ast(out, node->expr.rhs, depth + 1);
}

static int dump_debug(int argc, char **argv, const struct filter *flt)
{
  struct bpf_prog prog;
  struct filter norm;
  int i;

  printf("tokens:\n");
  if (!argc)
    printf("  <empty>\n");
  for (i = 0; i < argc; i++)
    printf("  [%d] %s\n", i, argv[i]);

  printf("parsed ast:\n");
  dump_ast(stdout, flt->root, 1);

  if (filter_normalize(&norm, flt) < 0)
    return -1;

  printf("normalized ast:\n");
  dump_ast(stdout, norm.root, 1);

  if (bpf_compile(&prog, flt) < 0) {
    filter_free(&norm);
    return -1;
  }

  printf("Warning: assuming Ethernet\n");
  bpf_dump(stdout, &prog);

  bpf_prog_free(&prog);
  filter_free(&norm);
  return 0;
}

int main(int argc, char **argv)
{
  struct capture_cfg cfg;
  struct filter flt;
  struct opts opts;
  const char *prog;
  int rc;

  if (parse_opts(&opts, argc, argv) < 0) {
    usage(stderr, argv[0]);
    return 1;
  }

  prog = strrchr(argv[0], '/');
  if (prog)
    prog++;
  else
    prog = argv[0];

  if (filter_parse(&flt, opts.filter_argc, opts.filter_argv) < 0)
    return 1;

  if (opts.debug) {
    rc = dump_debug(opts.filter_argc, opts.filter_argv, &flt);
    filter_free(&flt);
    return rc < 0;
  }

  cfg.progname = prog;
  cfg.ifname = opts.ifname;
  cfg.out_path = opts.out_path;
  cfg.filter = &flt;
  cfg.filter_mode = opts.filter_mode;
  cfg.snaplen = opts.snaplen ? opts.snaplen : PCAP_SNAPLEN;
  cfg.pkt_limit = opts.pkt_limit;
  cfg.time_limit = opts.time_limit;

  rc = capture_run(&cfg);
  filter_free(&flt);
  return rc < 0;
}
