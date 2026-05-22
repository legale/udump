#ifndef UDUMP_CAPTURE_H
#define UDUMP_CAPTURE_H

struct filter;

enum filter_mode {
  FILTER_MODE_BPF,
  FILTER_MODE_USER,
};

struct capture_cfg {
  const char *ifname;
  const char *out_path;
  const struct filter *filter;
  enum filter_mode filter_mode;
  unsigned long long pkt_limit;
  unsigned int time_limit;
};

int capture_run(const struct capture_cfg *cfg);

#endif
