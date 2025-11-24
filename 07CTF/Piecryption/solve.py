#!/usr/bin/env python3
# solve_decode.py
# Usage: put pi digits in pi-100m.txt and the ciphertext (comma separated ints) in ciphertext.txt
# Then run: python3 solve_decode.py

import sys
import os
from array import array
from bisect import bisect_left

# ---- load inputs ----
with open('100m.txt', 'r') as f:
    digits = f.read().strip()
N = len(digits)
ciphertext = [22, 11, 4, 22, 4, 1, 29, 4, 9, 63, 4, 11, 13, 18, 5, 4, 0, 4, 4, 12, 18, 13, 8, 16, 19, 4, 5, 11, 1, 0, 0, 8, 5, 3, 11, 2, 7, 3, 10, 13, 7, 16, 6, 12, 6, 5, 0, 5, 11, 8, 4, 9, 1, 3, 8, 18, 7, 3, 1, 15, 23, 24, 7, 30, 3, 21, 2, 19, 5, 8, 4, 0, 2, 1, 6, 36, 1, 5, 0, 1, 5, 11, 17, 0, 8, 5, 21, 5, 17, 3, 11]
L = len(ciphertext)

# cumulative sum to get absolute positions offset + cumulative[k]
cum = [0]*L
s = 0
for i,c in enumerate(ciphertext):
    s += c
    cum[i] = s
total_span = cum[-1]
print("Total span (last cumulative index):", total_span)

# quick helpers: build positions list for each digit 0..9
pos = [array('I') for _ in range(10)]
for i,ch in enumerate(digits):
    d = ord(ch) - 48
    pos[d].append(i)
for d in range(10):
    print(f"digit {d} occurrences: {len(pos[d])}")

# Given a candidate start_offset s0, check if it decodes correctly.
def try_start(s0):
    # ensure within bounds
    if s0 < 0 or s0 + total_span >= N:
        return None
    positions = []
    prev = s0
    for k, gap in enumerate(ciphertext):
        i = prev + gap  # expected absolute position for this encoded digit
        if i < 0 or i >= N:
            return None
        d = ord(digits[i]) - 48
        positions.append((i,d))
        # Now we must ensure there is NO occurrence of digit d in (prev, i)
        # find next occurrence of d at or after prev using pos[d] list:
        plist = pos[d]
        # find first index >= prev
        idx = bisect_left(plist, prev)
        if idx >= len(plist):
            return None
        if plist[idx] != i:
            # the first occurrence >= prev is not our i => invalid
            return None
        prev = i
    # If we reach here it's consistent; return digit string
    digit_str = ''.join(str(d) for (_,d) in positions)
    return digit_str

# Strategy to enumerate candidate start offsets:
# Instead of trying every s0 up to N (too slow), use first ciphertext element:
c0 = ciphertext[0]
print("First ciphertext gap c0 =", c0)
# For every position 'p' in digits where digits[p] is any digit,
# candidate s0 = p - c0 (must be >=0). But we only need p such that s0 >=0 and s0+total_span < N.
# We'll iterate digits 0..9 and their occurrence arrays; this is linear in total digit count (N),
# but checks are cheap b/c try_start fails fast usually.
found = 0
results = []
checked = 0
# Iterate over digits 0..9, through their positions
for d in range(10):
    plist = pos[d]
    for p in plist:
        s0 = p - c0
        if s0 < 0 or s0 + total_span >= N:
            continue
        checked += 1
        digitstr = try_start(s0)
        if digitstr is not None:
            print(f"Candidate start {s0} works, recovered {len(digitstr)} digits (first 50): {digitstr[:50]}")
            results.append((s0, digitstr))
            found += 1
            # optionally we can break early if we think unique
    # optional: show progress
    print(f"done digit {d}, checked candidates so far: {checked}, found: {found}")

print("Total candidates found:", found)

# Post-process candidates: try to convert digit string -> integer -> 38 bytes and check flag format
def digits_to_flag(ds):
    # remove any leading zeros? no: the encoder used decimal representation of the integer;
    # so we must interpret exactly as an integer
    try:
        val = int(ds)
    except:
        return None
    # convert to bytes: 38 bytes big-endian
    b = val.to_bytes(38, byteorder='big')
    try:
        s = b.decode('utf-8', errors='strict')
    except:
        # maybe printable ascii but not strict utf-8; try latin-1
        s = b.decode('latin-1', errors='replace')
    return b, s

for s0,dstr in results:
    b, s = digits_to_flag(dstr)
    print("start", s0, "-> ascii preview:", s[:80])
    if s.startswith("07CTF{") and s.endswith("}"):
        print("POSSIBLE FLAG FOUND:", s)
    else:
        # maybe there are leading zeros in decimal rep that cause mismatch; we can also try trimming leading zeros:
        dstr2 = dstr.lstrip('0')
        if dstr2=='':
            continue
        b2, s2 = digits_to_flag(dstr2)
        print("After stripping leading zeros ascii preview:", s2[:80])
        if s2.startswith("07CTF{") and s2.endswith("}"):
            print("POSSIBLE FLAG FOUND (after strip leading zeros):", s2)

print("Done. If nothing found, consider increasing logging or checking that pi-100m.txt matches exactly the generator's digits (they used [2:]).")