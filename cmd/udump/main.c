#include <getopt.h>
#include <stdio.h>
#include <string.h>

struct opts {
  const char *ifname;
  const char *out_path;
  int filter_argc;
  char **filter_argv;
};

static void usage(FILE *out, const char *prog)
{
  fprintf(out, "usage: %s -i <ifname> -w <output_file> [filter ...]\n", prog);
}

static int parse_opts(struct opts *opts, int argc, char **argv)
{
  int c;

  memset(opts, 0, sizeof(*opts));

  while ((c = getopt(argc, argv, "i:w:")) != -1) {
    switch (c) {
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
