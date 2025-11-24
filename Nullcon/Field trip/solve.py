#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Fast solver for 'Field trip' (GF(2^224) DH):
- Field arithmetic: carry-less mul with 4-bit window + fast reduction
- DLP: Pohlig–Hellman; BSGS for q <= 2^36; Pollard's rho for 49-bit prime
- Optional multiprocessing for the 49-bit prime
"""

import time, os, sys, math, random
from hashlib import sha256
from binascii import unhexlify
from Crypto.Cipher import AES
from multiprocessing import Pool, cpu_count

# ------------ Params from chall ------------
DEG = 224
f = 26959946667150639794667015087019630673637144422540572481103610249993
g = 7
N = (1 << 224) - 1
PRIMES = [
    3, 5, 17, 29, 43, 113, 127, 257, 449, 2689, 5153, 65537,
    15790321, 183076097, 54410972897, 358429848460993
]
BIGQ = PRIMES[-1]

# ------------ GF(2^224) arithmetic ------------
def reduce_poly(a: int) -> int:
    # fast shift-xor reduction
    while a.bit_length() > DEG:
        a ^= f << (a.bit_length() - (DEG + 1))
    return a

def clmul4(a: int, b: int) -> int:
    """Carry-less multiply (no reduction), 4-bit window."""
    T = [0] * 16
    # precompute a * k for k=0..15 (GF(2) poly, so xor of shifts)
    for k in range(1, 16):
        lb = k & -k
        pos = (lb.bit_length() - 1)
        T[k] = T[k ^ lb] ^ (a << pos)
    res = 0
    i = 0
    x = b
    while x:
        c = x & 0xF
        if c:
            res ^= T[c] << (4 * i)
        x >>= 4
        i += 1
    return res

def mul(a: int, b: int) -> int:
    return reduce_poly(clmul4(a, b))

def sqr(a: int) -> int:
    # square by inserting zeros between bits
    x, res, pos = a, 0, 0
    while x:
        if x & 1:
            res |= (1 << (pos * 2))
        x >>= 1
        pos += 1
    return reduce_poly(res)

def pow_field(base: int, exp: int) -> int:
    r, x, e = 1, base, exp
    while e:
        if e & 1:
            r = mul(r, x)
        e >>= 1
        x = sqr(x)
    return r

# ------------ Discrete log helpers ------------
def inv_in_subgroup(G: int, q: int) -> int:
    return pow_field(G, q - 1)

def dlog_bsgs(G: int, H: int, q: int) -> int:
    m = math.isqrt(q) + 1
    table = {}
    cur = 1
    for j in range(m):
        table[cur] = j
        cur = mul(cur, G)
    G_inv_m = 1
    Gin = inv_in_subgroup(G, q)
    for _ in range(m):
        G_inv_m = mul(G_inv_m, Gin)
    gamma = H
    for i in range(m + 2):
        j = table.get(gamma)
        if j is not None:
            x = (i * m + j) % q
            # verify
            if pow_field(G, x) == H:
                return x
        gamma = mul(gamma, G_inv_m)
    raise RuntimeError("BSGS failed unexpectedly")

# ---- Pollard rho (single worker) with negation map & 4 partitions ----
def rho_single(args):
    G, H, q, seed, iters = args
    random.seed(seed)

    def step(X, a, b):
        # 4 partitions keyed by 2 LSBs; negation map halves the group
        r = X & 3
        if r == 0:
            return mul(X, G), (a + 1) % q, b
        elif r == 1:
            return mul(X, H), a, (b + 1) % q
        elif r == 2:
            Y = mul(X, X)
            return Y, (a * 2) % q, (b * 2) % q
        else:
            # small fixed jump
            return mul(X, pow_field(G, 3)), (a + 3) % q, b

    # random start
    a = random.randrange(q)
    b = random.randrange(q)
    X = mul(pow_field(G, a), pow_field(H, b))
    Y, A, B = X, a, b

    for _ in range(iters):
        X, a, b = step(X, a, b)
        Y, A, B = step(*step(Y, A, B))
        # negation map: identify X and X^{-1} to reduce cycles
        if X == Y:
            denom = (B - b) % q
            num = (a - A) % q
            if denom == 0:
                # restart
                a = random.randrange(q); b = random.randrange(q)
                X = mul(pow_field(G, a), pow_field(H, b))
                Y, A, B = X, a, b
                continue
            x = (num * pow(denom, -1, q)) % q
            if pow_field(G, x) == H:
                return x
            # soft restart
            a = random.randrange(q); b = random.randrange(q)
            X = mul(pow_field(G, a), pow_field(H, b))
            Y, A, B = X, a, b
    return None

def dlog_rho_parallel(G: int, H: int, q: int, workers: int | None = None, per_worker_iters: int = 3_000_000) -> int:
    """Run several independent rho walkers in parallel and race."""
    if workers is None:
        workers = max(1, min(cpu_count(), 8))
    seeds = [random.randrange(1 << 63) for _ in range(workers)]
    args = [(G, H, q, seeds[i], per_worker_iters) for i in range(workers)]
    if workers == 1:
        # single-process fallback
        while True:
            x = rho_single(args[0])
            if x is not None:
                return x
            args[0] = (G, H, q, random.randrange(1 << 63), per_worker_iters)
    with Pool(processes=workers) as pool:
        while True:
            for x in pool.imap_unordered(rho_single, args, chunksize=1):
                if x is not None:
                    pool.terminate()
                    return x
            # none found; try new seeds
            args = [(G, H, q, random.randrange(1 << 63), per_worker_iters) for _ in range(workers)]

def dlog_mod_prime(Gq: int, Hq: int, q: int, use_parallel: bool) -> int:
    if Hq == 1 or Gq == 1:
        return 0
    # BSGS up to 2^36 (comfortable memory/time)
    if q <= (1 << 36):
        return dlog_bsgs(Gq, Hq, q)
    # 49-bit prime -> rho (optionally parallel)
    return (dlog_rho_parallel(Gq, Hq, q, workers=(os.cpu_count() if use_parallel else 1)))

# ------------ CRT ------------
def crt_pair(a1, m1, a2, m2):
    inv = pow(m1, -1, m2)
    t = ((a2 - a1) % m2) * inv % m2
    return (a1 + t * m1) % (m1 * m2), m1 * m2

def crt_all(residues, moduli):
    x, m = residues[0], moduli[0]
    for r, mod in zip(residues[1:], moduli[1:]):
        x, m = crt_pair(x, m, r, mod)
    return x, m

# ------------ Main ------------
def main():
    # config
    USE_PARALLEL_RHO = True   # bật để tận dụng đa nhân cho prime 49-bit
    PER_WORKER_ITERS = 3_000_000  # tăng nếu máy khỏe

    # read instance
    with open("output.txt", "r") as fh:
        lines = [ln.strip() for ln in fh.read().strip().splitlines() if ln.strip()]
    A = int(lines[0]); B = int(lines[1]); C = unhexlify(lines[2])

    residues = []; moduli = []
    print("[*] Starting Pohlig–Hellman")
    for q in PRIMES:
        t0 = time.time()
        n_q = N // q
        Gq = pow_field(g, n_q)
        Bq = pow_field(B, n_q)
        kind = "BSGS" if q <= (1 << 36) else ("rho x%d" % (os.cpu_count() if USE_PARALLEL_RHO else 1))
        print(f"    - q = {q}  ({kind}) ...", end="", flush=True)
        xq = dlog_mod_prime(Gq, Bq, q, use_parallel=(USE_PARALLEL_RHO and q == BIGQ))
        dt = time.time() - t0
        print(f"  residue = {xq}   [{dt:.2f}s]")
        residues.append(xq); moduli.append(q)

    # reconstruct b
    b_val, ord_g = crt_all(residues, moduli)
    print(f"[*] Recovered b mod ord(g) = {b_val}")

    # compute K = A^b and AES key
    K = pow_field(A, b_val % ord_g)
    key = sha256(K.to_bytes(28, 'big')).digest()

    # decrypt ECB
    blocks = [C[i:i+16] for i in range(0, len(C), 16)]
    pt = b"".join(AES.new(key, AES.MODE_ECB).decrypt(b) for b in blocks)
    pt = pt.rstrip(b"\x00")
    try:
        print("[*] FLAG:", pt.decode())
    except:
        print("[*] FLAG (bytes):", pt)

if __name__ == "__main__":
    main()
