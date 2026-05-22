#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "filter.h"

static int hex_digit(int ch)
{
  if (ch >= '0' && ch <= '9')
    return ch - '0';
  if (ch >= 'a' && ch <= 'f')
    return ch - 'a' + 10;
  if (ch >= 'A' && ch <= 'F')
    return ch - 'A' + 10;
  return -1;
}

static int parse_mac(const char *arg, unsigned char *mac)
{
  int hi;
  int lo;
  int i;

  for (i = 0; i < 6; i++) {
    hi = hex_digit(arg[0]);
    lo = hex_digit(arg[1]);
    if (hi < 0 || lo < 0)
      return -1;
    mac[i] = (unsigned char)((hi << 4) | lo);
    arg += 2;

    if (i == 5)
      break;
    if (*arg != ':')
      return -1;
    arg++;
  }

  return *arg ? -1 : 0;
}

static int parse_port(const char *arg, unsigned short *port)
{
  char *end;
  unsigned long val;

  errno = 0;
  val = strtoul(arg, &end, 10);
  if (errno || *arg == '\0' || *end != '\0' || val > 65535) {
    fprintf(stderr, "invalid port: %s\n", arg);
    return -1;
  }

  *port = (unsigned short)val;
  return 0;
}

static int need_more(const char *what)
{
  fprintf(stderr, "missing %s\n", what);
  return -1;
}

int filter_parse(struct filter *f, int argc, char **argv)
{
  struct filter_term *term;
  int i;

  memset(f, 0, sizeof(*f));

  if (!argc)
    return 0;

  f->terms = calloc((size_t)argc, sizeof(*f->terms));
  if (!f->terms) {
    perror("calloc");
    return -1;
  }

  i = 0;
  while (i < argc) {
    term = &f->terms[f->nterms];

    if (!strcmp(argv[i], "tcp")) {
      term->kind = TERM_TCP;
      f->nterms++;
      i++;
      continue;
    }

    if (!strcmp(argv[i], "udp")) {
      term->kind = TERM_UDP;
      f->nterms++;
      i++;
      continue;
    }

    if (!strcmp(argv[i], "port")) {
      if (i + 1 >= argc)
        goto err_port;
      if (parse_port(argv[i + 1], &term->port) < 0)
        goto err;
      term->kind = TERM_PORT;
      f->nterms++;
      i += 2;
      continue;
    }

    if (!strcmp(argv[i], "ether")) {
      if (i + 2 >= argc)
        goto err_ether;

      if (!strcmp(argv[i + 1], "src"))
        term->kind = TERM_ETHER_SRC;
      else if (!strcmp(argv[i + 1], "dst"))
        term->kind = TERM_ETHER_DST;
      else if (!strcmp(argv[i + 1], "host"))
        term->kind = TERM_ETHER_HOST;
      else {
        fprintf(stderr, "unsupported ether qualifier: %s\n", argv[i + 1]);
        goto err;
      }

      if (parse_mac(argv[i + 2], term->mac) < 0) {
        fprintf(stderr, "invalid mac: %s\n", argv[i + 2]);
        goto err;
      }

      f->nterms++;
      i += 3;
      continue;
    }

    fprintf(stderr, "unsupported filter token: %s\n", argv[i]);
    goto err;
  }

  return 0;

err_port:
  need_more("port value");
  goto err;
err_ether:
  need_more("ether filter");
err:
  filter_free(f);
  return -1;
}

void filter_free(struct filter *f)
{
  free(f->terms);
  f->terms = NULL;
  f->nterms = 0;
}
