#ifndef UDUMP_CAPTURE_H
#define UDUMP_CAPTURE_H

struct capture_cfg {
  const char *ifname;
  const char *out_path;
  unsigned long long pkt_limit;
  unsigned int time_limit;
};

int capture_run(const struct capture_cfg *cfg);

#endif
