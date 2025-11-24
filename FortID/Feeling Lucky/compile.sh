#!/usr/bin/env bash
set -euo pipefail

CFLAGS="-O2 -pipe -std=c99 -Wall -Wextra -Wno-unused-parameter -D_POSIX_C_SOURCE=200809L -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE"
LDFLAGS="-Wl,-z,relro,-z,now -Wl,-z,noexecstack -pie"

gcc $CFLAGS -c tweetnacl.c
gcc $CFLAGS -c chall.c
gcc $CFLAGS $LDFLAGS -o chall chall.o tweetnacl.o

echo "[+] Built ./chall"
