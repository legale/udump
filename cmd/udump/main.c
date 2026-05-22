#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bpf.h"
#include "capture.h"
#include "filter.h"

struct opts {
  int debug;
  const char *ifname;
  const char *out_path;
  enum filter_mode filter_mode;
  unsigned long long pkt_limit;
  unsigned int time_limit;
  int filter_argc;
  char **filter_argv;
};

static void usage(FILE *out, const char *prog)
{
  fprintf(out,
      "usage: %s [-d] [-i <ifname> -w <output_file>] [-c <count>] "
      "[-G <seconds>] "
      "[--filter-mode <bpf|user>] "
      "[filter ...]\n",
      prog);
}

static int parse_uint(const char *name, const char *arg, unsigned int *out)
{
  char *end;
  unsigned long val;

  errno = 0;
  val = strtoul(arg, &end, 10);
  if (errno || *arg == '\0' || *end != '\0' || val == 0 || val > UINT_MAX) {
    fprintf(stderr, "invalid %s: %s\n", name, arg);
    return -1;
  }

  *out = (unsigned int)val;
  return 0;
}

static int parse_ull(const char *name, const char *arg, unsigned long long *out)
{
  char *end;
  unsigned long long val;

  errno = 0;
  val = strtoull(arg, &end, 10);
  if (errno || *arg == '\0' || *end != '\0' || val == 0) {
    fprintf(stderr, "invalid %s: %s\n", name, arg);
    return -1;
  }

  *out = val;
  return 0;
}

static int parse_filter_mode(const char *arg, enum filter_mode *mode)
{
  if (!strcmp(arg, "bpf")) {
    *mode = FILTER_MODE_BPF;
    return 0;
  }

  if (!strcmp(arg, "user")) {
    *mode = FILTER_MODE_USER;
    return 0;
  }

  fprintf(stderr, "invalid filter mode: %s\n", arg);
  return -1;
}

static int parse_opts(struct opts *opts, int argc, char **argv)
{
  static const struct option long_opts[] = {
    { "filter-mode", required_argument, NULL, 1 },
    { NULL, 0, NULL, 0 },
  };
  int have_filter_mode;
  int c;

  memset(opts, 0, sizeof(*opts));
  opts->filter_mode = FILTER_MODE_BPF;
  have_filter_mode = 0;

  while ((c = getopt_long(argc, argv, "c:G:di:w:", long_opts, NULL)) != -1) {
    switch (c) {
    case 'c':
      if (opts->pkt_limit) {
        fprintf(stderr, "duplicate -c option\n");
        return -1;
      }
      if (parse_ull("-c", optarg, &opts->pkt_limit) < 0)
        return -1;
      break;
    case 'G':
      if (opts->time_limit) {
        fprintf(stderr, "duplicate -G option\n");
        return -1;
      }
      if (parse_uint("-G", optarg, &opts->time_limit) < 0)
        return -1;
      break;
    case 'd':
      if (opts->debug) {
        fprintf(stderr, "duplicate -d option\n");
        return -1;
      }
      opts->debug = 1;
      break;
    case 'i':
      if (opts->ifname) {
        fprintf(stderr, "duplicate -i option\n");
        return -1;
      }
      opts->ifname = optarg;
      break;
    case 'w':
      if (opts->out_path) {
        fprintf(stderr, "duplicate -w option\n");
        return -1;
      }
      opts->out_path = optarg;
      break;
    case 1:
      if (have_filter_mode) {
        fprintf(stderr, "duplicate --filter-mode option\n");
        return -1;
      }
      if (parse_filter_mode(optarg, &opts->filter_mode) < 0)
        return -1;
      have_filter_mode = 1;
      break;
    default:
      return -1;
    }
  }

  if (!opts->debug && !opts->ifname) {
    fprintf(stderr, "missing -i <ifname>\n");
    return -1;
  }

  if (!opts->debug && !opts->out_path) {
    fprintf(stderr, "missing -w <output_file>\n");
    return -1;
  }

  opts->filter_argc = argc - optind;
  opts->filter_argv = argv + optind;
  return 0;
}

static void dump_indent(FILE *out, int depth)
{
  while (depth-- > 0)
    fputs("  ", out);
}

static void dump_term(FILE *out, const struct filter_term *term)
{
  switch (term->kind) {
  case TERM_TCP:
    fputs("tcp", out);
    return;
  case TERM_UDP:
    fputs("udp", out);
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
  int rc;

  if (parse_opts(&opts, argc, argv) < 0) {
    usage(stderr, argv[0]);
    return 1;
  }

  if (filter_parse(&flt, opts.filter_argc, opts.filter_argv) < 0)
    return 1;

  if (opts.debug) {
    rc = dump_debug(opts.filter_argc, opts.filter_argv, &flt);
    filter_free(&flt);
    return rc < 0;
  }

  cfg.ifname = opts.ifname;
  cfg.out_path = opts.out_path;
  cfg.filter = &flt;
  cfg.filter_mode = opts.filter_mode;
  cfg.pkt_limit = opts.pkt_limit;
  cfg.time_limit = opts.time_limit;

  rc = capture_run(&cfg);
  filter_free(&flt);
  return rc < 0;
}
