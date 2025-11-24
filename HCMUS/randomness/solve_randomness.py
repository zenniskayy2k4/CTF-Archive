#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Crypto CTF - "randomness" solver
Assumptions (based on common patterns in such challenges):
- Coefficient matrix A is generated with Python's random seeded by int(time.time())
- A has size n x n, where n == len(value_list) (number of equations equals number of unknowns)
- Each entry of A is randint(1, 2**16)
- FLAG bytes vector x is length n (bytes of the secret flag)
- output.txt contains a line like: value_list = [ ... ]
What this script does:
- Parses output.txt to get b (value_list)
- Builds A for each candidate seed in a plausible time window around a provided timestamp
- Solves A x = b over rationals (exact arithmetic), checks x is all integers in [0,255]
- Validates flag shape starts with b"0160ca14{" and ends with b"}" (tweak if needed)
Usage:
    1) Put this script next to the provided "output.txt"
    2) Edit the TIMESTAMP_LOCAL string below to the claimed generation time (local time when the author ran the generator)
       For the given statement: "Created at 15/05/2025 - 11:27 AM", and files modified 11:26 AM,
       start with 2025-05-15 11:26:00 in Asia/Ho_Chi_Minh (UTC+7)
    3) Run: python3 solve_randomness.py
       It will try seeds within ±300 seconds by default (adjustable).
"""

import re, random, sys
from fractions import Fraction
from datetime import datetime, timedelta, timezone

# === Config you may tweak ===
# Local time when the generator likely ran (author's system time). Format: YYYY-MM-DD HH:MM:SS
TIMESTAMP_LOCAL = "2025-05-15 11:26:00"
# Local timezone offset (Asia/Ho_Chi_Minh is UTC+7)
LOCAL_UTC_OFFSET_HOURS = 7
# How many seconds to search around that time (both directions)
SEARCH_RADIUS_SECONDS = 300  # try ±5 minutes; widen if needed

# Known flag framing (adjust if your CTF uses different tag)
KNOWN_PREFIX = b"0160ca14{"
KNOWN_SUFFIX = b"}"

def parse_value_list(path="output.txt"):
    txt = open(path, "r", encoding="utf-8", errors="ignore").read()
    m = re.search(r"value_list\s*=\s*\[([^\]]*)\]", txt, re.S)
    if not m:
        raise RuntimeError("Couldn't find value_list = [...] in output.txt")
    inner = m.group(1)
    # Split on commas that separate integers
    nums = [int(x.strip()) for x in inner.replace("\n", " ").split(",") if x.strip()]
    return nums

def build_matrix(n, seed):
    random.seed(seed)
    A = [[random.randint(1, 2**16) for _ in range(n)] for __ in range(n)]
    return A

def gauss_solve_rational(A, b):
    """Solve A x = b over rationals, return list of Fractions (length n).
       Raises if matrix is singular."""
    n = len(A)
    # Build augmented matrix
    M = [list(map(Fraction, row)) + [Fraction(bi)] for row, bi in zip(A, b)]
    # Forward elimination
    r = 0
    for c in range(n):
        # find pivot
        piv = None
        for i in range(r, n):
            if M[i][c] != 0:
                piv = i; break
        if piv is None:
            raise RuntimeError("Singular matrix (no pivot in column {})".format(c))
        if piv != r:
            M[r], M[piv] = M[piv], M[r]
        # normalize row r
        factor = M[r][c]
        M[r] = [x / factor for x in M[r]]
        # eliminate other rows
        for i in range(n):
            if i == r: continue
            f = M[i][c]
            if f != 0:
                M[i] = [M[i][j] - f * M[r][j] for j in range(n+1)]
        r += 1
        if r == n:
            break
    # extract solution
    x = [M[i][n] for i in range(n)]
    return x

def try_seed(seed, b):
    n = len(b)
    A = build_matrix(n, seed)
    try:
        x = gauss_solve_rational(A, b)
    except Exception:
        return None
    # Check integrality and byte range
    xi = []
    for t in x:
        if t.denominator != 1:  # not integer
            return None
        v = t.numerator
        if not (0 <= v <= 255):
            return None
        xi.append(v)
    # Optional: check prefix/suffix if lengths fit
    bs = bytes(xi)
    if bs.startswith(KNOWN_PREFIX) and bs.endswith(KNOWN_SUFFIX):
        return bs
    # If not matching framing, still return bytes to allow manual inspection
    return bs

def main():
    b = parse_value_list("output.txt")
    n = len(b)
    print(f"[+] Loaded value_list with length n = {n}")
    # Build candidate seeds around provided local timestamp
    local_dt = datetime.strptime(TIMESTAMP_LOCAL, "%Y-%m-%d %H:%M:%S")
    # convert local to epoch seconds
    epoch = datetime(1970,1,1, tzinfo=timezone.utc)
    assumed_utc = (local_dt - timedelta(hours=LOCAL_UTC_OFFSET_HOURS)).replace(tzinfo=timezone.utc)
    center = int((assumed_utc - epoch).total_seconds())

    print(f"[+] Center epoch (UTC) from local time: {center}")
    tried = 0
    for delta in range(-SEARCH_RADIUS_SECONDS, SEARCH_RADIUS_SECONDS+1):
        seed = center + delta
        res = try_seed(seed, b)
        tried += 1
        if isinstance(res, (bytes, bytearray)):
            bs = bytes(res)
            # quick sanity check: printable-ish and framing
            if bs.startswith(KNOWN_PREFIX) and bs.endswith(KNOWN_SUFFIX):
                print(f"[!] FOUND plausible flag with seed={seed}: {bs!r}")
                print(bs.decode('latin1', errors='replace'))
                return
    print("[-] No unique flag found in the given window.")
    print("    Try widening SEARCH_RADIUS_SECONDS or double-check the local timestamp/timezone.")
    print("    If the system generated a rectangular matrix (m != n), adapt build_matrix() accordingly.")

if __name__ == "__main__":
    main()
