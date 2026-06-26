#ifndef UDUMP_CLI_H
#define UDUMP_CLI_H

#include <stdio.h>

#include "capture.h"

struct opts {
  int debug;
  int ether;
  const char *ifname;
  const char *out_path;
  enum filter_mode filter_mode;
  unsigned int snaplen;
  unsigned long long pkt_limit;
  unsigned int time_limit;
  int filter_argc;
  char **filter_argv;
};

int parse_opts(struct opts *opts, int argc, char **argv);
void usage(FILE *out, const char *prog);

#endif
