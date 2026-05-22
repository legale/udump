#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct opts {
  const char *ifname;
  const char *out_path;
  unsigned long long pkt_limit;
  unsigned int time_limit;
  int filter_argc;
  char **filter_argv;
};

static void usage(FILE *out, const char *prog)
{
  fprintf(out,
      "usage: %s -i <ifname> -w <output_file> [-c <count>] [-G <seconds>] "
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

static int parse_opts(struct opts *opts, int argc, char **argv)
{
  int c;

  memset(opts, 0, sizeof(*opts));

  while ((c = getopt(argc, argv, "c:G:i:w:")) != -1) {
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
    default:
      return -1;
    }
  }

  if (!opts->ifname) {
    fprintf(stderr, "missing -i <ifname>\n");
    return -1;
  }

  if (!opts->out_path) {
    fprintf(stderr, "missing -w <output_file>\n");
    return -1;
  }

  opts->filter_argc = argc - optind;
  opts->filter_argv = argv + optind;
  return 0;
}

int main(int argc, char **argv)
{
  struct opts opts;

  if (parse_opts(&opts, argc, argv) < 0) {
    usage(stderr, argv[0]);
    return 1;
  }

  (void)opts;
  return 0;
}
