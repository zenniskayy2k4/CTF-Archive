#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/random.h>
#include <unistd.h>

#include "tweetnacl.h"

#define NMAX 128
#define MMAX 256
#define TMAX (64 + MMAX)
#define IDLEN 32
#define MENU "1) create_user\n2) get_token\n3) redeem_token\n4) quit\n> "

void randombytes(unsigned char *p, unsigned long long n) {
  while (n) {
    ssize_t r = getrandom(p, n, 0);
    if (r < 0) {
      perror("getrandom");
      exit(1);
    }
    p += r;
    n -= (unsigned long long)r;
  }
}

static int hx(int c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  return -1;
}

static void rdline(char *buf, size_t cap) {
  if (!fgets(buf, cap, stdin)) {
    printf("bye");
    exit(0);
  }
  size_t n = strlen(buf);
  if (n && buf[n - 1] == '\n')
    buf[n - 1] = 0;
}

static void dechex32(unsigned char out[32], const char *s) {
  for (size_t i = 0; i < 32; ++i) {
    int hi = hx((unsigned char)s[2 * i]);
    int lo = hx((unsigned char)s[2 * i + 1]);
    if (hi < 0)
      hi = 0;
    if (lo < 0)
      lo = 0;
    out[i] = (unsigned char)((hi << 4) | lo);
  }
}

static void to_hex(char *dst, size_t dstcap, const unsigned char *src,
                   size_t n) {
  if (dstcap < 2 * n + 1) {
    printf("hexcap");
    exit(1);
  }
  static const char *H = "0123456789abcdef";
  for (size_t i = 0; i < n; ++i) {
    dst[2 * i + 0] = H[(src[i] >> 4) & 0xF];
    dst[2 * i + 1] = H[src[i] & 0xF];
  }
  dst[2 * n] = 0;
}

static void log_note(const char *tag, const char *fmt, void *ctx) {
  if (tag && *tag) {
    printf("[%s] ", tag);
  }
  printf(fmt, ctx);
  printf("\n");
}

struct rec {
  unsigned char p[32];
  unsigned char s[64];
  int used;
};
static struct rec DB[NMAX];

static int pick(const unsigned char id[32]) {
  for (int i = 0; i < NMAX; ++i) {
    if (!DB[i].used)
      continue;
    if (!strncmp((const char *)id, (const char *)DB[i].p, IDLEN))
      return i;
  }
  return -1;
}

static const char *cmdpick(void) {
  uint8_t r;
  randombytes(&r, 1);
  uint64_t j;
  randombytes((unsigned char *)&j, sizeof j);
  if (j == 0xDEADBEEFCAFEBABEULL)
    return "cat flag.txt";
  switch (r % 3) {
  case 0:
    return "ls";
  case 1:
    return "echo \"better luck next time\"";
  default:
    return "echo \"try harder!\"";
  }
}

static unsigned long long sign_blob(unsigned char *out, size_t outcap,
                                    const unsigned char *msg, size_t mlen,
                                    const unsigned char seed_pk[64],
                                    const unsigned char id[32]) {
  if (outcap < mlen + 64) {
    printf("oversize");
    exit(1);
  }
  unsigned char mix[64];
  memcpy(mix, seed_pk, 32);
  memcpy(mix + 32, id, 32);
  unsigned long long sl = 0;
  crypto_sign(out, &sl, msg, mlen, mix);
  return sl;
}

static void do_create(void) {
  int k = -1;
  for (int i = 0; i < NMAX; ++i)
    if (!DB[i].used) {
      k = i;
      break;
    }
  if (k < 0) {
    log_note("warn", "%s", "no slots");
    return;
  }
  if (crypto_sign_keypair(DB[k].p, DB[k].s) != 0) {
    log_note("err", "%s", "keygen failed");
    exit(1);
  }
  DB[k].used = 1;
  char pkhex[2 * 32 + 1];
  to_hex(pkhex, sizeof pkhex, DB[k].p, 32);
  printf("user_id(hex) = %s\n", pkhex);
}

static void do_token(void) {
  char idraw[2 * IDLEN + 512];
  unsigned char id[IDLEN];

  printf("user_id(hex)> ");
  fflush(stdout);
  rdline(idraw, sizeof idraw);
  dechex32(id, idraw);

  int k = pick(id);
  if (k < 0) {
    char emsg[2 * IDLEN + 32];
    snprintf(emsg, sizeof emsg, "unknown user id: %s", idraw);
    log_note("warn", "%s", emsg);
    return;
  }

  const char *cmd = cmdpick();
  size_t ml = strlen(cmd);
  if (ml > MMAX) {
    log_note("err", "%s", "internal err");
    exit(1);
  }

  unsigned char sig[64 + MMAX];
  unsigned long long bl =
      sign_blob(sig, sizeof sig, (const unsigned char *)cmd, ml, DB[k].s, id);

  char buf[2 * (64 + MMAX) + 1];
  to_hex(buf, sizeof buf, sig, bl);
  if (memcmp(DB[k].p, id, 32) == 0) {
    printf("token(hex) = %s\n", buf);
  } else {
    char linefmt[2 * IDLEN + 512];
    snprintf(linefmt, sizeof linefmt, "%s%s",
             "public key mismatch for user with id: ", idraw);
    log_note("warn", linefmt, buf);
  }
}

static void do_redeem(void) {
  char idraw[2 * IDLEN + 512];
  unsigned char id[IDLEN];

  printf("user_id(hex)> ");
  fflush(stdout);
  rdline(idraw, sizeof idraw);
  dechex32(id, idraw);

  int k = pick(id);
  if (k < 0) {
    char emsg[2 * IDLEN + 32];
    snprintf(emsg, sizeof emsg, "unknown user id: %s", idraw);
    log_note("warn", "%s", emsg);
    return;
  }

  char tok[2 * (TMAX) + 8];
  printf("token(hex)> ");
  fflush(stdout);
  rdline(tok, sizeof tok);

  size_t tl = strlen(tok);
  if (tl % 2) {
    log_note("warn", "%s", "bad token");
    return;
  }
  size_t sn = tl / 2;
  if (sn < 64 || sn > TMAX) {
    log_note("warn", "%s", "bad token");
    return;
  }

  unsigned char sm[TMAX];
  for (size_t i = 0; i < sn; ++i) {
    int hi = hx(tok[2 * i]), lo = hx(tok[2 * i + 1]);
    if (hi < 0 || lo < 0) {
      log_note("warn", "%s", "bad token hex");
      return;
    }
    sm[i] = (unsigned char)((hi << 4) | lo);
  }

  unsigned char m[TMAX];
  unsigned long long ml = 0;
  if (crypto_sign_open(m, &ml, sm, sn, DB[k].p) != 0) {
    log_note("warn", "%s", "invalid token");
    return;
  }
  if (ml >= MMAX) {
    log_note("warn", "%s", "cmd too long");
    return;
  }
  m[ml] = 0;

  int rc = system((char *)m);
  (void)rc;
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  printf("Do you feel lucky???\n\n");
  for (;;) {
    printf("%s", MENU);
    char line[32];
    rdline(line, sizeof line);
    if (!strcmp(line, "1") || !strcasecmp(line, "create_user"))
      do_create();
    else if (!strcmp(line, "2") || !strcasecmp(line, "get_token"))
      do_token();
    else if (!strcmp(line, "3") || !strcasecmp(line, "redeem_token"))
      do_redeem();
    else if (!strcmp(line, "4") || !strcasecmp(line, "quit") ||
             !strcasecmp(line, "exit")) {
      printf("bye");
      break;
    } else
      printf("?");
  }
  return 0;
}
