#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cli.h"

static char *argv0;

#define NEXT_ARG() \
  do { \
    argv++; \
    if (--argc <= 0) \
      incomplete_command(); \
  } while (0)
#define NEXT_ARG_OK() (argc - 1 > 0)
#define PREV_ARG() \
  do { \
    argv--; \
    argc++; \
  } while (0)

static void incomplete_command(void)
{
  fprintf(stdout, "Command line is not complete. Try -h or --help\n");
  exit(-1);
}

static bool matches(const char *prefix, const char *string)
{
  if (!*prefix)
    return false;
  while (*string && *prefix == *string) {
    prefix++;
    string++;
  }
  return !*prefix;
}

void usage(FILE *out, const char *prog)
{
  fprintf(out,
      "usage: %s [-d] [-e] [-s <snaplen>] [-i <ifname> -w <output_file>] "
      "[-c <count>] [-G <seconds>] "
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

int parse_opts(struct opts *opts, int argc, char **argv)
{
  int have_filter_mode;

  argv0 = *argv;
  memset(opts, 0, sizeof(*opts));
  opts->filter_mode = FILTER_MODE_BPF;
  have_filter_mode = 0;

  while (argc > 1) {
    NEXT_ARG();
    if (matches(*argv, "-h") || matches(*argv, "--help")) {
      usage(stdout, argv0);
      exit(0);
    } else if (matches(*argv, "-d")) {
      if (opts->debug) {
        fprintf(stderr, "duplicate -d option\n");
        return -1;
      }
      opts->debug = 1;
    } else if (matches(*argv, "-e")) {
      if (opts->ether) {
        fprintf(stderr, "duplicate -e option\n");
        return -1;
      }
      opts->ether = 1;
    } else if (matches(*argv, "-s")) {
      if (opts->snaplen) {
        fprintf(stderr, "duplicate -s option\n");
        return -1;
      }
      if (!NEXT_ARG_OK())
        incomplete_command();
      NEXT_ARG();
      if (parse_uint("-s", *argv, &opts->snaplen) < 0)
        return -1;
    } else if (matches(*argv, "-i")) {
      if (opts->ifname) {
        fprintf(stderr, "duplicate -i option\n");
        return -1;
      }
      if (!NEXT_ARG_OK())
        incomplete_command();
      NEXT_ARG();
      opts->ifname = *argv;
    } else if (matches(*argv, "-w")) {
      if (opts->out_path) {
        fprintf(stderr, "duplicate -w option\n");
        return -1;
      }
      if (!NEXT_ARG_OK())
        incomplete_command();
      NEXT_ARG();
      opts->out_path = *argv;
    } else if (matches(*argv, "-c")) {
      if (opts->pkt_limit) {
        fprintf(stderr, "duplicate -c option\n");
        return -1;
      }
      if (!NEXT_ARG_OK())
        incomplete_command();
      NEXT_ARG();
      if (parse_ull("-c", *argv, &opts->pkt_limit) < 0)
        return -1;
    } else if (matches(*argv, "-G")) {
      if (opts->time_limit) {
        fprintf(stderr, "duplicate -G option\n");
        return -1;
      }
      if (!NEXT_ARG_OK())
        incomplete_command();
      NEXT_ARG();
      if (parse_uint("-G", *argv, &opts->time_limit) < 0)
        return -1;
    } else if (matches(*argv, "--filter-mode")) {
      if (have_filter_mode) {
        fprintf(stderr, "duplicate --filter-mode option\n");
        return -1;
      }
      if (!NEXT_ARG_OK())
        incomplete_command();
      NEXT_ARG();
      if (parse_filter_mode(*argv, &opts->filter_mode) < 0)
        return -1;
      have_filter_mode = 1;
    } else {
      PREV_ARG();
      break;
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

  opts->filter_argc = argc - 1;
  opts->filter_argv = argv + 1;
  return 0;
}
