#include <errno.h>
#include <linux/bpf_common.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bpf.h"
#include "filter.h"

#define SNAPLEN 262144u
#define PATCH_JT 1
#define PATCH_JF 2

struct bpf_patch {
  unsigned short idx;
  unsigned char which;
};

struct bpf_patch_list {
  struct bpf_patch *items;
  unsigned short len;
  unsigned short cap;
};

struct bpf_block {
  unsigned short start;
  struct bpf_patch_list trues;
  struct bpf_patch_list falses;
};

static void patch_list_free(struct bpf_patch_list *list)
{
  free(list->items);
  memset(list, 0, sizeof(*list));
}

static int patch_list_grow(struct bpf_patch_list *list, unsigned short need)
{
  struct bpf_patch *tmp;
  unsigned short cap;

  cap = list->cap ? list->cap * 2 : 8;
  while (cap < need)
    cap *= 2;

  tmp = realloc(list->items, (size_t)cap * sizeof(*list->items));
  if (!tmp) {
    perror("realloc");
    return -1;
  }

  list->items = tmp;
  list->cap = cap;
  return 0;
}

static int patch_list_add(struct bpf_patch_list *list, unsigned short idx,
    unsigned char which)
{
  unsigned short need;

  need = list->len + 1;
  if (need > list->cap && patch_list_grow(list, need) < 0)
    return -1;

  list->items[list->len].idx = idx;
  list->items[list->len].which = which;
  list->len++;
  return 0;
}

static int patch_list_append(struct bpf_patch_list *dst,
    struct bpf_patch_list *src)
{
  unsigned short need;

  if (!src->len) {
    patch_list_free(src);
    return 0;
  }

  need = dst->len + src->len;
  if (need < dst->len) {
    fprintf(stderr, "bpf compiler: patch list overflow\n");
    return -1;
  }

  if (need > dst->cap && patch_list_grow(dst, need) < 0)
    return -1;

  memcpy(dst->items + dst->len, src->items,
      (size_t)src->len * sizeof(*src->items));
  dst->len = need;
  patch_list_free(src);
  return 0;
}

static void block_free(struct bpf_block *blk)
{
  patch_list_free(&blk->trues);
  patch_list_free(&blk->falses);
  memset(blk, 0, sizeof(*blk));
}

static void bpf_prog_reset(struct bpf_prog *prog)
{
  free(prog->insns);
  memset(prog, 0, sizeof(*prog));
}

static int bpf_prog_grow(struct bpf_prog *prog)
{
  struct sock_filter *tmp;
  unsigned short cap;

  cap = prog->cap ? prog->cap * 2 : 32;
  tmp = realloc(prog->insns, (size_t)cap * sizeof(*prog->insns));
  if (!tmp) {
    perror("realloc");
    return -1;
  }

  prog->insns = tmp;
  prog->cap = cap;
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

static int patch_list_apply(struct bpf_prog *prog,
    struct bpf_patch_list *list, unsigned short target)
{
  struct sock_filter *insn;
  unsigned short i;
  unsigned int delta;

  for (i = 0; i < list->len; i++) {
    delta = (unsigned int)target - (unsigned int)list->items[i].idx - 1;
    if (delta > 255) {
      fprintf(stderr, "bpf compiler: jump too large\n");
      return -1;
    }

    insn = &prog->insns[list->items[i].idx];
    if (list->items[i].which == PATCH_JT)
      insn->jt = (unsigned char)delta;
    else
      insn->jf = (unsigned char)delta;
  }

  patch_list_free(list);
  return 0;
}

static int block_and(struct bpf_prog *prog, struct bpf_block *lhs,
    struct bpf_block *rhs, struct bpf_block *out)
{
  memset(out, 0, sizeof(*out));

  if (patch_list_apply(prog, &lhs->trues, rhs->start) < 0)
    return -1;

  out->start = lhs->start;
  out->trues = rhs->trues;
  memset(&rhs->trues, 0, sizeof(rhs->trues));
  out->falses = lhs->falses;
  memset(&lhs->falses, 0, sizeof(lhs->falses));
  if (patch_list_append(&out->falses, &rhs->falses) < 0) {
    block_free(out);
    return -1;
  }

  return 0;
}

static int block_or(struct bpf_prog *prog, struct bpf_block *lhs,
    struct bpf_block *rhs, struct bpf_block *out)
{
  memset(out, 0, sizeof(*out));

  if (patch_list_apply(prog, &lhs->falses, rhs->start) < 0)
    return -1;

  out->start = lhs->start;
  out->trues = lhs->trues;
  memset(&lhs->trues, 0, sizeof(lhs->trues));
  if (patch_list_append(&out->trues, &rhs->trues) < 0) {
    block_free(out);
    return -1;
  }
  out->falses = rhs->falses;
  memset(&rhs->falses, 0, sizeof(rhs->falses));
  return 0;
}

static int block_test_abs(struct bpf_prog *prog, unsigned short width,
    unsigned int off, unsigned short op, unsigned int k, int true_is_jt,
    struct bpf_block *blk)
{
  unsigned short idx;

  memset(blk, 0, sizeof(*blk));
  blk->start = prog->len;

  if (bpf_emit_stmt(prog, BPF_LD | width | BPF_ABS, off) < 0)
    return -1;

  idx = prog->len;
  if (bpf_emit_jump(prog, BPF_JMP | op | BPF_K, k, 0, 0) < 0)
    return -1;

  if (true_is_jt) {
    if (patch_list_add(&blk->trues, idx, PATCH_JT) < 0)
      goto err;
    if (patch_list_add(&blk->falses, idx, PATCH_JF) < 0)
      goto err;
  } else {
    if (patch_list_add(&blk->trues, idx, PATCH_JF) < 0)
      goto err;
    if (patch_list_add(&blk->falses, idx, PATCH_JT) < 0)
      goto err;
  }

  return 0;

err:
  block_free(blk);
  return -1;
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

static int compile_mac_eq(struct bpf_prog *prog, unsigned int off,
    const unsigned char *mac, struct bpf_block *out)
{
  struct bpf_block lhs;
  struct bpf_block rhs;

  if (block_test_abs(prog, BPF_W, off, BPF_JEQ, mac_word(mac, 0), 1, &lhs) < 0)
    return -1;
  if (block_test_abs(prog, BPF_H, off + 4, BPF_JEQ,
      mac_half(mac, 4), 1, &rhs) < 0) {
    block_free(&lhs);
    return -1;
  }
  if (block_and(prog, &lhs, &rhs, out) < 0) {
    block_free(&lhs);
    block_free(&rhs);
    return -1;
  }
  return 0;
}

static int compile_ipv4_proto(struct bpf_prog *prog, unsigned int proto,
    struct bpf_block *out)
{
  struct bpf_block lhs;
  struct bpf_block rhs;

  if (block_test_abs(prog, BPF_H, 12, BPF_JEQ, 0x0800, 1, &lhs) < 0)
    return -1;
  if (block_test_abs(prog, BPF_B, 23, BPF_JEQ, proto, 1, &rhs) < 0) {
    block_free(&lhs);
    return -1;
  }
  if (block_and(prog, &lhs, &rhs, out) < 0) {
    block_free(&lhs);
    block_free(&rhs);
    return -1;
  }
  return 0;
}

static int compile_ipv6_proto(struct bpf_prog *prog, unsigned int proto,
    struct bpf_block *out)
{
  struct bpf_block lhs;
  struct bpf_block rhs;

  if (block_test_abs(prog, BPF_H, 12, BPF_JEQ, 0x86dd, 1, &lhs) < 0)
    return -1;
  if (block_test_abs(prog, BPF_B, 20, BPF_JEQ, proto, 1, &rhs) < 0) {
    block_free(&lhs);
    return -1;
  }
  if (block_and(prog, &lhs, &rhs, out) < 0) {
    block_free(&lhs);
    block_free(&rhs);
    return -1;
  }
  return 0;
}

static int compile_ipv4_l4_proto(struct bpf_prog *prog, int proto,
    struct bpf_block *blk)
{
  unsigned short idx1;
  unsigned short idx2;

  if (proto == 6 || proto == 17)
    return block_test_abs(prog, BPF_B, 23, BPF_JEQ, (unsigned int)proto, 1, blk);

  memset(blk, 0, sizeof(*blk));
  blk->start = prog->len;

  if (bpf_emit_stmt(prog, BPF_LD | BPF_B | BPF_ABS, 23) < 0)
    return -1;

  idx1 = prog->len;
  if (bpf_emit_jump(prog, BPF_JMP | BPF_JEQ | BPF_K, 6, 0, 0) < 0)
    return -1;
  idx2 = prog->len;
  if (bpf_emit_jump(prog, BPF_JMP | BPF_JEQ | BPF_K, 17, 0, 0) < 0)
    return -1;

  if (patch_list_add(&blk->trues, idx1, PATCH_JT) < 0)
    goto err;
  if (patch_list_add(&blk->trues, idx2, PATCH_JT) < 0)
    goto err;
  if (patch_list_add(&blk->falses, idx2, PATCH_JF) < 0)
    goto err;
  return 0;

err:
  block_free(blk);
  return -1;
}

static int compile_ipv6_l4_proto(struct bpf_prog *prog, int proto,
    struct bpf_block *blk)
{
  unsigned short idx1;
  unsigned short idx2;

  if (proto == 6 || proto == 17)
    return block_test_abs(prog, BPF_B, 20, BPF_JEQ, (unsigned int)proto, 1, blk);

  memset(blk, 0, sizeof(*blk));
  blk->start = prog->len;

  if (bpf_emit_stmt(prog, BPF_LD | BPF_B | BPF_ABS, 20) < 0)
    return -1;

  idx1 = prog->len;
  if (bpf_emit_jump(prog, BPF_JMP | BPF_JEQ | BPF_K, 6, 0, 0) < 0)
    return -1;
  idx2 = prog->len;
  if (bpf_emit_jump(prog, BPF_JMP | BPF_JEQ | BPF_K, 17, 0, 0) < 0)
    return -1;

  if (patch_list_add(&blk->trues, idx1, PATCH_JT) < 0)
    goto err;
  if (patch_list_add(&blk->trues, idx2, PATCH_JT) < 0)
    goto err;
  if (patch_list_add(&blk->falses, idx2, PATCH_JF) < 0)
    goto err;
  return 0;

err:
  block_free(blk);
  return -1;
}

static int compile_ipv4_not_frag(struct bpf_prog *prog, struct bpf_block *blk)
{
  return block_test_abs(prog, BPF_H, 20, BPF_JSET, 0x1fff, 0, blk);
}

static int compile_ipv4_port_cmp(struct bpf_prog *prog, unsigned short port,
    struct bpf_block *blk)
{
  unsigned short idx1;
  unsigned short idx2;

  memset(blk, 0, sizeof(*blk));
  blk->start = prog->len;

  if (bpf_emit_stmt(prog, BPF_LDX | BPF_MSH | BPF_B, 14) < 0)
    return -1;
  if (bpf_emit_stmt(prog, BPF_LD | BPF_H | BPF_IND, 14) < 0)
    return -1;

  idx1 = prog->len;
  if (bpf_emit_jump(prog, BPF_JMP | BPF_JEQ | BPF_K, port, 0, 0) < 0)
    return -1;

  if (bpf_emit_stmt(prog, BPF_LD | BPF_H | BPF_IND, 16) < 0)
    return -1;

  idx2 = prog->len;
  if (bpf_emit_jump(prog, BPF_JMP | BPF_JEQ | BPF_K, port, 0, 0) < 0)
    return -1;

  if (patch_list_add(&blk->trues, idx1, PATCH_JT) < 0)
    goto err;
  if (patch_list_add(&blk->trues, idx2, PATCH_JT) < 0)
    goto err;
  if (patch_list_add(&blk->falses, idx2, PATCH_JF) < 0)
    goto err;
  return 0;

err:
  block_free(blk);
  return -1;
}

static int compile_ipv6_port_cmp(struct bpf_prog *prog, unsigned short port,
    struct bpf_block *blk)
{
  unsigned short idx1;
  unsigned short idx2;

  memset(blk, 0, sizeof(*blk));
  blk->start = prog->len;

  if (bpf_emit_stmt(prog, BPF_LD | BPF_H | BPF_ABS, 54) < 0)
    return -1;

  idx1 = prog->len;
  if (bpf_emit_jump(prog, BPF_JMP | BPF_JEQ | BPF_K, port, 0, 0) < 0)
    return -1;

  if (bpf_emit_stmt(prog, BPF_LD | BPF_H | BPF_ABS, 56) < 0)
    return -1;

  idx2 = prog->len;
  if (bpf_emit_jump(prog, BPF_JMP | BPF_JEQ | BPF_K, port, 0, 0) < 0)
    return -1;

  if (patch_list_add(&blk->trues, idx1, PATCH_JT) < 0)
    goto err;
  if (patch_list_add(&blk->trues, idx2, PATCH_JT) < 0)
    goto err;
  if (patch_list_add(&blk->falses, idx2, PATCH_JF) < 0)
    goto err;
  return 0;

err:
  block_free(blk);
  return -1;
}

static int compile_ipv4_port(struct bpf_prog *prog, int proto,
    unsigned short port, struct bpf_block *out)
{
  struct bpf_block eth;
  struct bpf_block l4;
  struct bpf_block frag;
  struct bpf_block cmp;
  struct bpf_block tmp1;
  struct bpf_block tmp2;

  if (block_test_abs(prog, BPF_H, 12, BPF_JEQ, 0x0800, 1, &eth) < 0)
    return -1;
  if (compile_ipv4_l4_proto(prog, proto, &l4) < 0) {
    block_free(&eth);
    return -1;
  }
  if (compile_ipv4_not_frag(prog, &frag) < 0) {
    block_free(&eth);
    block_free(&l4);
    return -1;
  }
  if (compile_ipv4_port_cmp(prog, port, &cmp) < 0) {
    block_free(&eth);
    block_free(&l4);
    block_free(&frag);
    return -1;
  }
  if (block_and(prog, &eth, &l4, &tmp1) < 0)
    goto err;
  if (block_and(prog, &tmp1, &frag, &tmp2) < 0)
    goto err_tmp1;
  if (block_and(prog, &tmp2, &cmp, out) < 0)
    goto err_tmp2;
  return 0;

err_tmp2:
  block_free(&tmp2);
err_tmp1:
  block_free(&tmp1);
err:
  block_free(&eth);
  block_free(&l4);
  block_free(&frag);
  block_free(&cmp);
  return -1;
}

static int compile_ipv6_port(struct bpf_prog *prog, int proto,
    unsigned short port, struct bpf_block *out)
{
  struct bpf_block eth;
  struct bpf_block l4;
  struct bpf_block cmp;
  struct bpf_block tmp;

  if (block_test_abs(prog, BPF_H, 12, BPF_JEQ, 0x86dd, 1, &eth) < 0)
    return -1;
  if (compile_ipv6_l4_proto(prog, proto, &l4) < 0) {
    block_free(&eth);
    return -1;
  }
  if (compile_ipv6_port_cmp(prog, port, &cmp) < 0) {
    block_free(&eth);
    block_free(&l4);
    return -1;
  }
  if (block_and(prog, &eth, &l4, &tmp) < 0)
    goto err;
  if (block_and(prog, &tmp, &cmp, out) < 0) {
    block_free(&tmp);
    goto err;
  }
  return 0;

err:
  block_free(&eth);
  block_free(&l4);
  block_free(&cmp);
  return -1;
}

static int compile_term_block(struct bpf_prog *prog,
    const struct filter_term *term, struct bpf_block *out)
{
  struct bpf_block lhs;
  struct bpf_block rhs;

  switch (term->kind) {
  case TERM_TCP:
    if (compile_ipv4_proto(prog, 6, &lhs) < 0)
      return -1;
    if (compile_ipv6_proto(prog, 6, &rhs) < 0) {
      block_free(&lhs);
      return -1;
    }
    if (block_or(prog, &lhs, &rhs, out) < 0) {
      block_free(&lhs);
      block_free(&rhs);
      return -1;
    }
    return 0;
  case TERM_UDP:
    if (compile_ipv4_proto(prog, 17, &lhs) < 0)
      return -1;
    if (compile_ipv6_proto(prog, 17, &rhs) < 0) {
      block_free(&lhs);
      return -1;
    }
    if (block_or(prog, &lhs, &rhs, out) < 0) {
      block_free(&lhs);
      block_free(&rhs);
      return -1;
    }
    return 0;
  case TERM_PORT:
    if (compile_ipv6_port(prog, 0, term->port, &lhs) < 0)
      return -1;
    if (compile_ipv4_port(prog, 0, term->port, &rhs) < 0) {
      block_free(&lhs);
      return -1;
    }
    if (block_or(prog, &lhs, &rhs, out) < 0) {
      block_free(&lhs);
      block_free(&rhs);
      return -1;
    }
    return 0;
  case TERM_ETHER_SRC:
    return compile_mac_eq(prog, 6, term->mac, out);
  case TERM_ETHER_DST:
    return compile_mac_eq(prog, 0, term->mac, out);
  case TERM_ETHER_HOST:
    if (compile_mac_eq(prog, 6, term->mac, &lhs) < 0)
      return -1;
    if (compile_mac_eq(prog, 0, term->mac, &rhs) < 0) {
      block_free(&lhs);
      return -1;
    }
    if (block_or(prog, &lhs, &rhs, out) < 0) {
      block_free(&lhs);
      block_free(&rhs);
      return -1;
    }
    return 0;
  }

  fprintf(stderr, "bpf compiler: unsupported term kind: %d\n", term->kind);
  return -1;
}

static int compile_node_block(struct bpf_prog *prog, const struct filter_node *node,
    struct bpf_block *out)
{
  struct bpf_block lhs;
  struct bpf_block rhs;

  switch (node->kind) {
  case NODE_TERM:
    return compile_term_block(prog, &node->term, out);
  case NODE_AND:
    if (compile_node_block(prog, node->expr.lhs, &lhs) < 0)
      return -1;
    if (compile_node_block(prog, node->expr.rhs, &rhs) < 0) {
      block_free(&lhs);
      return -1;
    }
    if (block_and(prog, &lhs, &rhs, out) < 0) {
      block_free(&lhs);
      block_free(&rhs);
      return -1;
    }
    return 0;
  case NODE_OR:
    if (compile_node_block(prog, node->expr.lhs, &lhs) < 0)
      return -1;
    if (compile_node_block(prog, node->expr.rhs, &rhs) < 0) {
      block_free(&lhs);
      return -1;
    }
    if (block_or(prog, &lhs, &rhs, out) < 0) {
      block_free(&lhs);
      block_free(&rhs);
      return -1;
    }
    return 0;
  }

  fprintf(stderr, "bpf compiler: bad node kind: %d\n", node->kind);
  return -1;
}

int bpf_compile(struct bpf_prog *prog, const struct filter *f)
{
  struct bpf_block root;
  unsigned short accept;
  unsigned short reject;

  memset(prog, 0, sizeof(*prog));

  if (!f->root)
    return bpf_emit_stmt(prog, BPF_RET | BPF_K, SNAPLEN);

  if (compile_node_block(prog, f->root, &root) < 0)
    goto err;

  accept = prog->len;
  if (bpf_emit_stmt(prog, BPF_RET | BPF_K, SNAPLEN) < 0)
    goto err_root;
  reject = prog->len;
  if (bpf_emit_stmt(prog, BPF_RET | BPF_K, 0) < 0)
    goto err_root;

  if (patch_list_apply(prog, &root.trues, accept) < 0)
    goto err_root;
  if (patch_list_apply(prog, &root.falses, reject) < 0)
    goto err_root;

  return 0;

err_root:
  block_free(&root);
err:
  bpf_prog_reset(prog);
  return -1;
}

void bpf_prog_free(struct bpf_prog *prog)
{
  bpf_prog_reset(prog);
}

struct sock_fprog bpf_sock_fprog(const struct bpf_prog *prog)
{
  struct sock_fprog fprog;

  fprog.len = prog->len;
  fprog.filter = prog->insns;
  return fprog;
}
