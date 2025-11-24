#!/usr/bin/env python3
"""
exploit_heuristic.py
Usage:
    python exploit_heuristic.py encrypted.bin

Output:
    decrypted_greedy.bin and decrypted_hillclimb.bin in working directory.
"""
import math, random, time
from pathlib import Path

CHUNK_SIZE = 256
REPEAT = 1337
PREFIX_BLOCKS = 200   # number of blocks used to compute score; tuneable
HILLCLIMB_ITERS = 20000
SEED = 0

def compute_D(counter):
    s = str(counter).encode()
    data = s * REPEAT
    D = bytearray(CHUNK_SIZE)
    for i in range(0, len(data), CHUNK_SIZE):
        chunk = data[i:i+CHUNK_SIZE]
        if len(chunk) < CHUNK_SIZE:
            chunk = chunk + b'\x00' * (CHUNK_SIZE - len(chunk))
        for j in range(CHUNK_SIZE):
            D[j] ^= chunk[j]
    return bytes(D)

def xor_bytes(a,b):
    return bytes(x ^ y for x,y in zip(a,b))

def score_matrix(C_blocks, D_list, prefix):
    # build a simple english-like byte probability
    byte_prob = [1e-9]*256
    for b in range(256):
        if b == 32: byte_prob[b] = 0.18
        elif b in (10,13): byte_prob[b] = 0.02
        elif 65 <= b <= 90 or 97 <= b <= 122: byte_prob[b] = 0.06
        elif 48 <= b <= 57: byte_prob[b] = 0.02
        elif 33 <= b <= 126: byte_prob[b] = 0.01
        else: byte_prob[b] = 1e-6
    s = sum(byte_prob)
    byte_prob = [p/s for p in byte_prob]
    logp = [math.log(p) for p in byte_prob]

    score = [[0.0]*CHUNK_SIZE for _ in range(CHUNK_SIZE)]
    start = time.time()
    for p in range(CHUNK_SIZE):
        Dcol = [D_list[i][p] for i in range(prefix)]
        for q in range(CHUNK_SIZE):
            ssum = 0.0
            for i in range(prefix):
                b = C_blocks[i][q] ^ Dcol[i]
                ssum += logp[b]
            score[p][q] = ssum
        if (p+1) % 32 == 0:
            print(f"Scored p {p+1} time elapsed {time.time()-start:.1f}s")
    print("Score matrix computed in %.1fs" % (time.time()-start))
    return score

def greedy_assignment(score):
    pairs = []
    for p in range(CHUNK_SIZE):
        for q in range(CHUNK_SIZE):
            pairs.append((score[p][q], p, q))
    pairs.sort(reverse=True, key=lambda x: x[0])

    perm = [-1]*CHUNK_SIZE
    used_p = set()
    used_q = set()
    for sc,p,q in pairs:
        if p in used_p or q in used_q: continue
        perm[p] = q
        used_p.add(p); used_q.add(q)
        if len(used_p) == CHUNK_SIZE:
            break
    if any(x==-1 for x in perm):
        raise RuntimeError("greedy failed to produce full permutation")
    return perm

def total_score(perm, score):
    return sum(score[p][perm[p]] for p in range(CHUNK_SIZE))

def hillclimb(perm, score, iters=HILLCLIMB_ITERS):
    random.seed(SEED)
    best = perm[:]
    best_score = total_score(best, score)
    improvements = 0
    for it in range(iters):
        a = random.randrange(CHUNK_SIZE)
        b = random.randrange(CHUNK_SIZE)
        if a == b: continue
        qa = best[a]; qb = best[b]
        delta = score[a][qb] + score[b][qa] - score[a][qa] - score[b][qb]
        if delta > 0:
            best[a], best[b] = qb, qa
            best_score += delta
            improvements += 1
        if (it+1) % 2000 == 0:
            print("Iter", it+1, "improvements", improvements, "best_score", best_score)
    print("Hillclimb done. improvements:", improvements, "best_score:", best_score)
    return best

def decrypt_with_perm(C_blocks, D_list, perm):
    out = bytearray()
    num_blocks = len(C_blocks)
    for i in range(num_blocks):
        D = D_list[i]
        K = bytearray(CHUNK_SIZE)
        for p in range(CHUNK_SIZE):
            q = perm[p]
            K[q] = D[p]
        out.extend(bytes(x ^ y for x,y in zip(C_blocks[i], K)))
    return bytes(out)

def main(enc_path):
    C = Path(enc_path).read_bytes()
    num_blocks = len(C) // CHUNK_SIZE
    C_blocks = [C[i*CHUNK_SIZE:(i+1)*CHUNK_SIZE] for i in range(num_blocks)]
    print("Encrypted:", len(C), "bytes,", num_blocks, "blocks")

    print("Computing D_list...")
    D_list = [compute_D(i) for i in range(num_blocks)]
    prefix = min(PREFIX_BLOCKS, num_blocks)
    print("Using prefix length:", prefix)

    score = score_matrix(C_blocks, D_list, prefix)
    perm = greedy_assignment(score)
    print("Greedy perm found. Computing decrypted_greedy.bin ...")
    plaintext = decrypt_with_perm(C_blocks, D_list, perm)
    Path("decrypted_greedy.bin").write_bytes(plaintext)
    print("Wrote decrypted_greedy.bin — printable ratio:",
          sum(1 for b in plaintext if 32 <= b <= 126 or b in (9,10,13)) / len(plaintext))

    print("Running hillclimb to improve perm ...")
    best_perm = hillclimb(perm, score)
    plaintext2 = decrypt_with_perm(C_blocks, D_list, best_perm)
    Path("decrypted_hillclimb.bin").write_bytes(plaintext2)
    print("Wrote decrypted_hillclimb.bin — printable ratio:",
          sum(1 for b in plaintext2 if 32 <= b <= 126 or b in (9,10,13)) / len(plaintext2))
    print("Done.")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python exploit_heuristic.py encrypted.bin")
        sys.exit(1)
    main(sys.argv[1])
