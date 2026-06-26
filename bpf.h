#ifndef UDUMP_BPF_H
#define UDUMP_BPF_H

#include <linux/filter.h>
#include <stdio.h>

struct filter;

enum bpf_link_kind {
  BPF_LINK_ETHERNET,
  BPF_LINK_IP,
};

struct bpf_prog {
  struct sock_filter *insns;
  unsigned short len;
  unsigned short cap;
};

int bpf_compile(struct bpf_prog *prog, const struct filter *f);
int bpf_compile_link(struct bpf_prog *prog, const struct filter *f,
    enum bpf_link_kind link);
void bpf_dump(FILE *out, const struct bpf_prog *prog);
void bpf_prog_free(struct bpf_prog *prog);
struct sock_fprog bpf_sock_fprog(const struct bpf_prog *prog);

#endif
