# Solver for the provided encryption scheme (reverse of main.py)
# This will:
# 1. Read cipher.txt (expects same base91 alphabet as in main.py)
# 2. Base91-decode -> bytes
# 3. Affine decrypt with a=7, b=13 mod 256
# 4. Recover AES_KEY (which was str(mtime).encode()) using the known prefix DCTF{
#    by solving for key bytes (key consists of ASCII digits)
# 5. Try candidate keys and output any plaintext matching DCTF{...}
#
# If cipher.txt is not present, the script will abort.
#
# NOTE: This brute-force tries key lengths between 6 and 12 (inclusive).
# For key lengths where not all key bytes are determined by the prefix,
# it will brute-force the remaining digits (bounded combinatorially).
# That is generally quite feasible for the typical timestamp length (10).

from itertools import product
import os
import sys
import re

B91_ALPHABET = [chr(i) for i in range(33, 124)]
A = 7
B = 13
PREFIX = b"DCTF{"

def base91_decode(s: str) -> bytes:
    if len(s) % 2 != 0:
        raise ValueError("Invalid base91 length")
    out = []
    for i in range(0, len(s), 2):
        hi_char = s[i]
        lo_char = s[i+1]
        try:
            hi = B91_ALPHABET.index(hi_char)
            lo = B91_ALPHABET.index(lo_char)
        except ValueError:
            raise ValueError(f"Invalid base91 character: {hi_char} or {lo_char}")
        val = hi * len(B91_ALPHABET) + lo
        out.append(val)
    return bytes(out)

def modinv(a, m=256):
    t, newt = 0, 1
    r, newr = m, a
    while newr != 0:
        q = r // newr
        t, newt = newt, t - q * newt
        r, newr = newr, r - q * newr
    if r > 1:
        raise ValueError("Not invertible")
    if t < 0:
        t += m
    return t

A_INV = modinv(A, 256)

def affine_decrypt(data: bytes) -> bytes:
    return bytes([(A_INV * (c - B)) % 256 for c in data])

def xor_with_key(data: bytes, key: bytes) -> bytes:
    return bytes([c ^ key[i % len(key)] for i, c in enumerate(data)])

def is_printable(b: bytes):
    try:
        text = b.decode('utf-8')
    except:
        return False
    # allow typical printable range plus newline/tab
    return all(32 <= ord(ch) < 127 or ch in '\r\n\t' for ch in text)

def try_recover(cipherfile="cipher.txt"):
    if not os.path.exists(cipherfile):
        print(f"[-] {cipherfile} not found in workspace. Put the ciphertext file here.")
        return

    s = open(cipherfile, "r", encoding="utf-8").read().strip()
    try:
        decoded = base91_decode(s)
    except Exception as e:
        print("Base91 decode failed:", e)
        return

    affdec = affine_decrypt(decoded)

    # We'll try key lengths that are plausible for epoch-second strings (commonly 9-10 digits),
    # but include a slightly broader range for robustness.
    results = []
    for key_len in range(6, 13):  # 6..12
        # constraints from prefix: for i in range(len(PREFIX)) set key[i % key_len] = affdec[i] ^ PREFIX[i]
        constraints = {}
        ok = True
        for i in range(len(PREFIX)):
            kpos = i % key_len
            kb = affdec[i] ^ PREFIX[i]
            if kpos in constraints and constraints[kpos] != kb:
                ok = False
                break
            constraints[kpos] = kb
        if not ok:
            continue

        # Check constrained bytes are digits
        bad = False
        for v in constraints.values():
            if not (48 <= v <= 57):
                bad = True
                break
        if bad:
            continue

        # Identify unknown positions
        unknown_positions = [pos for pos in range(key_len) if pos not in constraints]
        # If too many unknown positions, skip (safeguard). But generally key_len<=12 so unknowns <=7.
        if len(unknown_positions) > 7:
            continue

        # Enumerate possible digits for unknown positions
        total_combos = 10 ** len(unknown_positions)
        if total_combos > 2000000:
            # skip overly large brute force combos
            continue

        print(f"[+] Trying key length {key_len}, known positions {len(constraints)}, unknowns {len(unknown_positions)} (combos: {total_combos})")
        # prepare base key array
        base_key = [None] * key_len
        for pos, val in constraints.items():
            base_key[pos] = val

        # iterate over products for unknowns
        for digits in product(range(48, 58), repeat=len(unknown_positions)):
            key_arr = base_key.copy()
            for p, d in zip(unknown_positions, digits):
                key_arr[p] = d
            key_bytes = bytes(key_arr)
            # disallow leading zero (some timestamps don't have leading zero)
            # but timestamp may start with '1' or '0' rarely; we'll check numeric validity later
            try:
                key_str = key_bytes.decode('ascii')
            except:
                continue
            # ensure all digits
            if not key_str.isdigit():
                continue
            # optional plausibility check: epoch range reasonable
            ts = int(key_str)
            # allow timestamps between 2000-01-01 and 2025-12-31
            if ts < 946684800 or ts > 1767225599:
                continue

            # decrypt
            plaintext = xor_with_key(affdec, key_bytes)
            if not plaintext.startswith(PREFIX):
                continue
            if not is_printable(plaintext):
                continue
            # quick regex for DCTF{...}
            try:
                txt = plaintext.decode('utf-8')
            except:
                continue
            if re.search(r"DCTF\{.*?\}", txt):
                print("[*] Found candidate key:", key_str)
                print("[*] Plaintext:")
                print(txt)
                results.append((key_str, txt))
                # stop early for this key length (could find multiple; but usually one)
                # break

    if not results:
        print("[-] No candidate found with this strategy. Options:")
        print("    - Expand key length search range")
        print("    - Provide cipher.txt here (if not present)")
        print("    - If the flag timestamp was outside 2000..2025, adjust epoch bounds in the script.")
    else:
        print(f"[+] Found {len(results)} candidate(s).")

if __name__ == '__main__':
    try_recover("cipher.txt")
