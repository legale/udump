#include <errno.h>
#include <linux/bpf_common.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bpf.h"
#include "filter.h"

#define SNAPLEN 65535u

static void bpf_prog_reset(struct bpf_prog *prog)
{
  free(prog->insns);
  free(prog->fails);
  memset(prog, 0, sizeof(*prog));
}

static int bpf_prog_grow(struct bpf_prog *prog)
{
  struct sock_filter *tmp;
  unsigned short cap;

  cap = prog->cap ? prog->cap * 2 : 16;
  tmp = realloc(prog->insns, (size_t)cap * sizeof(*prog->insns));
  if (!tmp) {
    perror("realloc");
    return -1;
  }

  prog->insns = tmp;
  prog->cap = cap;
  return 0;
}

static int bpf_fail_grow(struct bpf_prog *prog)
{
  unsigned short *tmp;
  unsigned short cap;

  cap = prog->fail_cap ? prog->fail_cap * 2 : 16;
  tmp = realloc(prog->fails, (size_t)cap * sizeof(*prog->fails));
  if (!tmp) {
    perror("realloc");
    return -1;
  }

  prog->fails = tmp;
  prog->fail_cap = cap;
  return 0;
}

static int bpf_emit(struct bpf_prog *prog, struct sock_filter insn)
{
  if (prog->len == prog->cap && bpf_prog_grow(prog) < 0)
    return -1;

  prog->insns[prog->len++] = insn;
  return 0;
}

static int bpf_emit_stmt(struct bpf_prog *prog, unsigned short code,
    unsigned int k)
{
  struct sock_filter insn;

  memset(&insn, 0, sizeof(insn));
  insn.code = code;
  insn.k = k;
  return bpf_emit(prog, insn);
}

static int bpf_emit_fail_jump(struct bpf_prog *prog, unsigned short code,
    unsigned int k)
{
  struct sock_filter insn;

  if (prog->nfails == prog->fail_cap && bpf_fail_grow(prog) < 0)
    return -1;

  memset(&insn, 0, sizeof(insn));
  insn.code = code;
  insn.k = k;
  prog->fails[prog->nfails++] = prog->len;
  return bpf_emit(prog, insn);
}

static int bpf_emit_jump(struct bpf_prog *prog, unsigned short code,
    unsigned int k, unsigned char jt, unsigned char jf)
{
  struct sock_filter insn;

  memset(&insn, 0, sizeof(insn));
  insn.code = code;
  insn.jt = jt;
  insn.jf = jf;
  insn.k = k;
  return bpf_emit(prog, insn);
}

static unsigned int mac_word(const unsigned char *mac, int off)
{
  return ((unsigned int)mac[off + 0] << 24) |
      ((unsigned int)mac[off + 1] << 16) |
      ((unsigned int)mac[off + 2] << 8) |
      (unsigned int)mac[off + 3];
}

static unsigned int mac_half(const unsigned char *mac, int off)
{
  return ((unsigned int)mac[off + 0] << 8) |
      (unsigned int)mac[off + 1];
}

static int bpf_emit_mac_eq(struct bpf_prog *prog, unsigned int off,
    const unsigned char *mac)
{
  if (bpf_emit_stmt(prog, BPF_LD | BPF_W | BPF_ABS, off) < 0)
    return -1;
  if (bpf_emit_fail_jump(prog, BPF_JMP | BPF_JEQ | BPF_K, mac_word(mac, 0)) < 0)
    return -1;
  if (bpf_emit_stmt(prog, BPF_LD | BPF_H | BPF_ABS, off + 4) < 0)
    return -1;
  if (bpf_emit_fail_jump(prog, BPF_JMP | BPF_JEQ | BPF_K, mac_half(mac, 4)) < 0)
    return -1;
  return 0;
}

static int bpf_emit_mac_host(struct bpf_prog *prog, const unsigned char *mac)
{
  if (bpf_emit_stmt(prog, BPF_LD | BPF_W | BPF_ABS, 6) < 0)
    return -1;
  if (bpf_emit_jump(prog, BPF_JMP | BPF_JEQ | BPF_K,
      mac_word(mac, 0), 0, 2) < 0)
    return -1;
  if (bpf_emit_stmt(prog, BPF_LD | BPF_H | BPF_ABS, 10) < 0)
    return -1;
  if (bpf_emit_jump(prog, BPF_JMP | BPF_JEQ | BPF_K,
      mac_half(mac, 4), 4, 0) < 0)
    return -1;
  if (bpf_emit_stmt(prog, BPF_LD | BPF_W | BPF_ABS, 0) < 0)
    return -1;
  if (bpf_emit_fail_jump(prog, BPF_JMP | BPF_JEQ | BPF_K, mac_word(mac, 0)) < 0)
    return -1;
  if (bpf_emit_stmt(prog, BPF_LD | BPF_H | BPF_ABS, 4) < 0)
    return -1;
  if (bpf_emit_fail_jump(prog, BPF_JMP | BPF_JEQ | BPF_K, mac_half(mac, 4)) < 0)
    return -1;
  return 0;
}

static int bpf_compile_term(struct bpf_prog *prog, const struct filter_term *term)
{
  switch (term->kind) {
  case TERM_ETHER_SRC:
    return bpf_emit_mac_eq(prog, 6, term->mac);
  case TERM_ETHER_DST:
    return bpf_emit_mac_eq(prog, 0, term->mac);
  case TERM_ETHER_HOST:
    return bpf_emit_mac_host(prog, term->mac);
  default:
    fprintf(stderr, "bpf compiler: unsupported term kind: %d\n", term->kind);
    return -1;
  }
}

static int bpf_patch_fails(struct bpf_prog *prog)
{
  unsigned short reject;
  unsigned short idx;
  unsigned short i;
  unsigned int delta;

  if (bpf_emit_stmt(prog, BPF_RET | BPF_K, SNAPLEN) < 0)
    return -1;
  reject = prog->len;
  if (bpf_emit_stmt(prog, BPF_RET | BPF_K, 0) < 0)
    return -1;

  for (i = 0; i < prog->nfails; i++) {
    idx = prog->fails[i];
    delta = (unsigned int)reject - (unsigned int)idx - 1;
    if (delta > 255) {
      fprintf(stderr, "bpf compiler: jump too large\n");
      return -1;
    }
    prog->insns[idx].jf = (unsigned char)delta;
  }

  return 0;
}

int bpf_compile(struct bpf_prog *prog, const struct filter *f)
{
  int i;

  memset(prog, 0, sizeof(*prog));

  if (!f->nterms)
    return bpf_emit_stmt(prog, BPF_RET | BPF_K, SNAPLEN);

  for (i = 0; i < f->nterms; i++) {
    if (bpf_compile_term(prog, &f->terms[i]) < 0)
      goto err;
  }

  if (bpf_patch_fails(prog) < 0)
    goto err;

  return 0;

err:
  bpf_prog_reset(prog);
  return -1;
}

void bpf_prog_free(struct bpf_prog *prog)
{
  bpf_prog_reset(prog);
}

struct sock_fprog bpf_sock_fprog(struct bpf_prog *prog)
{
  struct sock_fprog fprog;

  fprog.len = prog->len;
  fprog.filter = prog->insns;
  return fprog;
}
