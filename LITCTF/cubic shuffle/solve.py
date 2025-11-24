#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# LITCTF "cubic shuffle" — full solver (meet-in-the-middle + symbolic MT19937)
# Requires: pip install z3-solver

import socket, sys, time, string, copy, collections, math
from dataclasses import dataclass
from typing import List, Dict
from z3 import *

HOST = "litctf.org"
PORT = 31786

# ---------------------------
# Cube logic (ported from obs.py)
# ---------------------------

def cubify(a: str):
    return [[list(b[i:i+3]) for i in range(0, len(b), 3)] for b in [a[i:i+9] for i in range(0, len(a), 9)]]

def linify(a: list):
    return ''.join([''.join([''.join(c) for c in b]) for b in a])

def U_Turn(cube):
    tmp = cube[1][0]; cube[1][0]=cube[2][0]; cube[2][0]=cube[3][0]; cube[3][0]=cube[4][0]; cube[4][0]=tmp
    tmp = cube[0][0][0]; cube[0][0][0]=cube[0][2][0]; cube[0][2][0]=cube[0][2][2]; cube[0][2][2]=cube[0][0][2]; cube[0][0][2]=tmp
    tmp = cube[0][0][1]; cube[0][0][1]=cube[0][1][0]; cube[0][1][0]=cube[0][2][1]; cube[0][2][1]=cube[0][1][2]; cube[0][1][2]=tmp

def U_Turn_Prime(cube):
    tmp = cube[1][0]; cube[1][0]=cube[4][0]; cube[4][0]=cube[3][0]; cube[3][0]=cube[2][0]; cube[2][0]=tmp
    tmp = cube[0][0][0]; cube[0][0][0]=cube[0][0][2]; cube[0][0][2]=cube[0][2][2]; cube[0][2][2]=cube[0][2][0]; cube[0][2][0]=tmp
    tmp = cube[0][0][1]; cube[0][0][1]=cube[0][1][2]; cube[0][1][2]=cube[0][2][1]; cube[0][2][1]=cube[0][1][0]; cube[0][1][0]=tmp

def L_Turn(cube):
    tmp = [cube[2][0][0], cube[2][1][0], cube[2][2][0]]
    cube[2][0][0]=cube[0][0][0]; cube[2][1][0]=cube[0][1][0]; cube[2][2][0]=cube[0][2][0]
    cube[0][0][0]=cube[4][2][2]; cube[0][1][0]=cube[4][1][2]; cube[0][2][0]=cube[4][0][2]
    cube[4][0][2]=cube[5][2][0]; cube[4][1][2]=cube[5][1][0]; cube[4][2][2]=cube[5][0][0]
    cube[5][0][0]=tmp[0]; cube[5][1][0]=tmp[1]; cube[5][2][0]=tmp[2]
    tmp = cube[1][0][0]; cube[1][0][0]=cube[1][2][0]; cube[1][2][0]=cube[1][2][2]; cube[1][2][2]=cube[1][0][2]; cube[1][0][2]=tmp
    tmp = cube[1][0][1]; cube[1][0][1]=cube[1][1][0]; cube[1][1][0]=cube[1][2][1]; cube[1][2][1]=cube[1][1][2]; cube[1][1][2]=tmp

def L_Turn_Prime(cube):
    tmp = [cube[4][2][2], cube[4][1][2], cube[4][0][2]]
    cube[4][0][2]=cube[0][2][0]; cube[4][1][2]=cube[0][1][0]; cube[4][2][2]=cube[0][0][0]
    cube[0][0][0]=cube[2][0][0]; cube[0][1][0]=cube[2][1][0]; cube[0][2][0]=cube[2][2][0]
    cube[2][0][0]=cube[5][0][0]; cube[2][1][0]=cube[5][1][0]; cube[2][2][0]=cube[5][2][0]
    cube[5][0][0]=tmp[0]; cube[5][1][0]=tmp[1]; cube[5][2][0]=tmp[2]
    tmp = cube[1][0][0]; cube[1][0][0]=cube[1][0][2]; cube[1][0][2]=cube[1][2][2]; cube[1][2][2]=cube[1][2][0]; cube[1][2][0]=tmp
    tmp = cube[1][0][1]; cube[1][0][1]=cube[1][1][2]; cube[1][1][2]=cube[1][2][1]; cube[1][2][1]=cube[1][1][0]; cube[1][1][0]=tmp

def F_Turn(cube):
    tmp = [cube[0][2][0], cube[0][2][1], cube[0][2][2]]
    cube[0][2][0]=cube[1][2][2]; cube[0][2][1]=cube[1][1][2]; cube[0][2][2]=cube[1][0][2]
    cube[1][2][2]=cube[5][0][2]; cube[1][1][2]=cube[5][0][1]; cube[1][0][2]=cube[5][0][0]
    cube[5][0][2]=cube[3][0][0]; cube[5][0][1]=cube[3][1][0]; cube[5][0][0]=cube[3][2][0]
    cube[3][0][0]=tmp[0]; cube[3][1][0]=tmp[1]; cube[3][2][0]=tmp[2]
    tmp = cube[2][0][0]; cube[2][0][0]=cube[2][2][0]; cube[2][2][0]=cube[2][2][2]; cube[2][2][2]=cube[2][0][2]; cube[2][0][2]=tmp
    tmp = cube[2][0][1]; cube[2][0][1]=cube[2][1][0]; cube[2][1][0]=cube[2][2][1]; cube[2][2][1]=cube[2][1][2]; cube[2][1][2]=tmp

def F_Turn_Prime(cube):
    tmp = [cube[3][0][0], cube[3][1][0], cube[3][2][0]]
    cube[3][0][0]=cube[5][0][2]; cube[3][1][0]=cube[5][0][1]; cube[3][2][0]=cube[5][0][0]
    cube[5][0][2]=cube[1][2][2]; cube[5][0][1]=cube[1][1][2]; cube[5][0][0]=cube[1][0][2]
    cube[1][2][2]=cube[0][2][0]; cube[1][1][2]=cube[0][2][1]; cube[1][0][2]=cube[0][2][2]
    cube[0][2][0]=tmp[0]; cube[0][2][1]=tmp[1]; cube[0][2][2]=tmp[2]
    tmp = cube[2][0][0]; cube[2][0][0]=cube[2][0][2]; cube[2][0][2]=cube[2][2][2]; cube[2][2][2]=cube[2][2][0]; cube[2][2][0]=tmp
    tmp = cube[2][0][1]; cube[2][0][1]=cube[2][1][2]; cube[2][1][2]=cube[2][2][1]; cube[2][2][1]=cube[2][1][0]; cube[2][1][0]=tmp

def R_Turn(cube):
    tmp = [cube[5][0][2], cube[5][1][2], cube[5][2][2]]
    cube[5][0][2]=cube[4][2][0]; cube[5][1][2]=cube[4][1][0]; cube[5][2][2]=cube[4][0][0]
    cube[4][0][0]=cube[0][2][2]; cube[4][1][0]=cube[0][1][2]; cube[4][2][0]=cube[0][0][2]
    cube[0][0][2]=cube[2][0][2]; cube[0][1][2]=cube[2][1][2]; cube[0][2][2]=cube[2][2][2]
    cube[2][0][2]=tmp[0]; cube[2][1][2]=tmp[1]; cube[2][2][2]=tmp[2]
    tmp = cube[3][0][0]; cube[3][0][0]=cube[3][2][0]; cube[3][2][0]=cube[3][2][2]; cube[3][2][2]=cube[3][0][2]; cube[3][0][2]=tmp
    tmp = cube[3][0][1]; cube[3][0][1]=cube[3][1][0]; cube[3][1][0]=cube[3][2][1]; cube[3][2][1]=cube[3][1][2]; cube[3][1][2]=tmp

def R_Turn_Prime(cube):
    tmp = [cube[2][0][2], cube[2][1][2], cube[2][2][2]]
    cube[2][0][2]=cube[0][0][2]; cube[2][1][2]=cube[0][1][2]; cube[2][2][2]=cube[0][2][2]
    cube[0][2][2]=cube[4][0][0]; cube[0][1][2]=cube[4][1][0]; cube[0][0][2]=cube[4][2][0]
    cube[4][2][0]=cube[5][0][2]; cube[4][1][0]=cube[5][1][2]; cube[4][0][0]=cube[5][2][2]
    cube[5][0][2]=tmp[0]; cube[5][1][2]=tmp[1]; cube[5][2][2]=tmp[2]
    tmp = cube[3][0][0]; cube[3][0][0]=cube[3][0][2]; cube[3][0][2]=cube[3][2][2]; cube[3][2][2]=cube[3][2][0]; cube[3][2][0]=tmp
    tmp = cube[3][0][1]; cube[3][0][1]=cube[3][1][2]; cube[3][1][2]=cube[3][2][1]; cube[3][2][1]=cube[3][1][0]; cube[3][1][0]=tmp

def B_Turn(cube):
    tmp = [cube[0][0][2], cube[0][0][1], cube[0][0][0]]
    cube[0][0][0]=cube[3][0][2]; cube[0][0][1]=cube[3][1][2]; cube[0][0][2]=cube[3][2][2]
    cube[3][0][2]=cube[5][2][2]; cube[3][1][2]=cube[5][2][1]; cube[3][2][2]=cube[5][2][0]
    cube[5][2][0]=cube[1][0][0]; cube[5][2][1]=cube[1][1][0]; cube[5][2][2]=cube[1][2][0]
    cube[1][0][0]=tmp[0]; cube[1][1][0]=tmp[1]; cube[1][2][0]=tmp[2]
    tmp = cube[4][0][0]; cube[4][0][0]=cube[4][2][0]; cube[4][2][0]=cube[4][2][2]; cube[4][2][2]=cube[4][0][2]; cube[4][0][2]=tmp
    tmp = cube[4][0][1]; cube[4][0][1]=cube[4][1][0]; cube[4][1][0]=cube[4][2][1]; cube[4][2][1]=cube[4][1][2]; cube[4][1][2]=tmp

def B_Turn_Prime(cube):
    tmp = [cube[1][0][0], cube[1][1][0], cube[1][2][0]]
    cube[1][0][0]=cube[5][2][0]; cube[1][1][0]=cube[5][2][1]; cube[1][2][0]=cube[5][2][2]
    cube[5][2][2]=cube[3][0][2]; cube[5][2][1]=cube[3][1][2]; cube[5][2][0]=cube[3][2][2]
    cube[3][0][2]=cube[0][0][0]; cube[3][1][2]=cube[0][0][1]; cube[3][2][2]=cube[0][0][2]
    cube[0][0][2]=tmp[0]; cube[0][0][1]=tmp[1]; cube[0][0][0]=tmp[2]
    tmp = cube[4][0][0]; cube[4][0][0]=cube[4][0][2]; cube[4][0][2]=cube[4][2][2]; cube[4][2][2]=cube[4][2][0]; cube[4][2][0]=tmp
    tmp = cube[4][0][1]; cube[4][0][1]=cube[4][1][2]; cube[4][1][2]=cube[4][2][1]; cube[4][2][1]=cube[4][1][0]; cube[4][1][0]=tmp

def D_Turn(cube):
    tmp = [cube[3][2][0], cube[3][2][1], cube[3][2][2]]
    cube[3][2][0]=cube[2][2][0]; cube[3][2][1]=cube[2][2][1]; cube[3][2][2]=cube[2][2][2]
    cube[2][2][0]=cube[1][2][0]; cube[2][2][1]=cube[1][2][1]; cube[2][2][2]=cube[1][2][2]
    cube[1][2][0]=cube[4][2][0]; cube[1][2][1]=cube[4][2][1]; cube[1][2][2]=cube[4][2][2]
    cube[4][2][0]=tmp[0]; cube[4][2][1]=tmp[1]; cube[4][2][2]=tmp[2]
    tmp = cube[5][0][0]; cube[5][0][0]=cube[5][2][0]; cube[5][2][0]=cube[5][2][2]; cube[5][2][2]=cube[5][0][2]; cube[5][0][2]=tmp
    tmp = cube[5][0][1]; cube[5][0][1]=cube[5][1][2]; cube[5][1][2]=cube[5][2][1]; cube[5][2][1]=cube[5][1][0]; cube[5][1][0]=tmp

def D_Turn_Prime(cube):
    tmp = [cube[4][2][0], cube[4][2][1], cube[4][2][2]]
    cube[4][2][0]=cube[1][2][0]; cube[4][2][1]=cube[1][2][1]; cube[4][2][2]=cube[1][2][2]
    cube[1][2][0]=cube[2][2][0]; cube[1][2][1]=cube[2][2][1]; cube[1][2][2]=cube[2][2][2]
    cube[2][2][0]=cube[3][2][0]; cube[2][2][1]=cube[3][2][1]; cube[2][2][2]=cube[3][2][2]
    cube[3][2][0]=tmp[0]; cube[3][2][1]=tmp[1]; cube[3][2][2]=tmp[2]
    tmp = cube[5][0][0]; cube[5][0][0]=cube[5][0][2]; cube[5][0][2]=cube[5][2][2]; cube[5][2][2]=cube[5][2][0]; cube[5][2][0]=tmp
    tmp = cube[5][0][1]; cube[5][0][1]=cube[5][1][2]; cube[5][1][2]=cube[5][2][1]; cube[5][2][1]=cube[5][1][0]; cube[5][1][0]=tmp

CALLER = {
    0: U_Turn, 1: lambda cb: (U_Turn(cb), U_Turn(cb)), 2: U_Turn_Prime,
    3: D_Turn, 4: lambda cb: (D_Turn(cb), D_Turn(cb)), 5: D_Turn_Prime,
    6: L_Turn, 7: lambda cb: (L_Turn(cb), L_Turn(cb)), 8: L_Turn_Prime,
    9: R_Turn,10: lambda cb: (R_Turn(cb), R_Turn(cb)),11: R_Turn_Prime,
    12:F_Turn,13: lambda cb: (F_Turn(cb), F_Turn(cb)),14: F_Turn_Prime,
    15:B_Turn,16: lambda cb: (B_Turn(cb), B_Turn(cb)),17: B_Turn_Prime
}
INV = {0:2, 1:1, 2:0, 3:5, 4:4, 5:3, 6:8, 7:7, 8:6, 9:11, 10:10, 11:9, 12:14, 13:13, 14:12, 15:17, 16:16, 17:15}

OG = string.ascii_letters + "01"
OG_CUBE = cubify(OG)

def apply_moves(cube, moves):
    cb = copy.deepcopy(cube)
    for m in moves:
        CALLER[m](cb)
    return cb

# ---------------------------
# Meet-in-the-middle depth=5
# ---------------------------

def gen_forward(depth=5):
    states = {linify(OG_CUBE): [[]]}
    for _ in range(depth):
        nxt = collections.defaultdict(list)
        for s, seqs in states.items():
            base = cubify(s)
            for m in range(18):
                cb = copy.deepcopy(base)
                CALLER[m](cb)
                ss = linify(cb)
                for seq in seqs:
                    if seq and INV[m] == seq[-1]:
                        continue
                    nxt[ss].append(seq + [m])
        states = nxt
    return states

def backward_sequences(target: str, depth=5) -> Dict[str, List[List[int]]]:
    states = {target: [[]]}
    for _ in range(depth):
        nxt = collections.defaultdict(list)
        for s, seqs in states.items():
            base = cubify(s)
            for m in range(18):
                cb = copy.deepcopy(base)
                # inverse move
                CALLER[INV[m]](cb)
                ss = linify(cb)
                for seq in seqs:
                    if seq and INV[m] == seq[-1]:
                        continue
                    nxt[ss].append(seq + [m])
        states = nxt
    return states

def enumerate_len10(terminal: str) -> List[List[int]]:
    global FWD5
    back = backward_sequences(terminal, 5)
    res = []
    for mid_state, back_seqs in back.items():
        if mid_state not in FWD5:
            continue
        for fseq in FWD5[mid_state]:
            for bseq in back_seqs:
                res.append(fseq + bseq[::-1])
    return res

FWD5 = None

# ---------------------------
# PRNG.n() constraints (obs.py)
# ---------------------------

def step0_candidates(m0: int) -> List[int]:
    out = [m0]
    if m0 <= 13:
        out.append(m0 + 18)
    return out  # 5-bit chunk in {m0, m0+18(if <=31)}

def next_step_candidates(prev_move: int, mi: int) -> List[int]:
    base = ((prev_move // 6) + 1) * 6  # 6,12,18(=0) modulo 18
    sols = []
    for q in range(16):  # 4-bit chunk 0..15, mapped by %12 then offset
        r = q % 12
        if (base + r) % 18 == mi:
            sols.append(q)
    return sols

@dataclass
class Run:
    out: str  # server output (linify)
    cands: List[List[int]]  # all 10-move sequences

# ---------------------------
# Symbolic MT19937 (full twist + temper)
# ---------------------------

N, M = 624, 397
MATRIX_A = 0x9908B0DF
UPPER_MASK = 0x80000000
LOWER_MASK = 0x7FFFFFFF

def solve_mt_from_runs(runs: List[Run], words_budget=5000):
    s = Solver()
    # State vars
    st = [BitVec(f"st_{i}", 32) for i in range(N)]
    # Produce many outputs
    outs = []
    cur = list(st)
    for t in range(words_budget):
        i = t % N
        j = (i + 1) % N
        k = (i + M) % N
        y = (cur[i] & BitVecVal(UPPER_MASK,32)) | (cur[j] & BitVecVal(LOWER_MASK,32))
        xA = LShR(y,1) ^ If((cur[j] & 1) != 0, BitVecVal(MATRIX_A,32), BitVecVal(0,32))
        new_word = cur[k] ^ xA
        cur[i] = new_word
        # temper
        y1 = new_word ^ LShR(new_word, 11)
        y2 = y1 ^ ((y1 << 7) & BitVecVal(0x9D2C5680, 32))
        y3 = y2 ^ ((y2 << 15) & BitVecVal(0xEFC60000, 32))
        y4 = y3 ^ LShR(y3, 18)
        outs.append(y4)

    def get_bits(off, n):
        word_idx = off // 32
        intra = off % 32
        if intra + n <= 32:
            w = outs[word_idx]
            hi = 31 - intra
            lo = 31 - (intra + n) + 1
            return Extract(hi, lo, w)
        else:
            first = 32 - intra
            second = n - first
            a = get_bits(off, first)
            b = get_bits(off + first, second)
            return Concat(a, b)

    # Build Or-of-branches per run, consuming fixed 41 bits each
    off = 0
    for r in runs:
        branches = []
        for mv in r.cands:
            # translate this candidate sequence to 10 chunks
            cons = []
            # step 0: 5 bits
            b5 = get_bits(off, 5)
            c5 = step0_candidates(mv[0])
            cons.append(Or(*[b5 == BitVecVal(v,5) for v in c5]))
            # steps 1..9: 4 bits each
            prev = mv[0]
            cur_off = off + 5
            ok = True
            for i in range(1,10):
                b4 = get_bits(cur_off, 4)
                cs = next_step_candidates(prev, mv[i])
                if not cs:
                    ok = False
                    break
                cons.append(Or(*[b4 == BitVecVal(v,4) for v in cs]))
                prev = mv[i]
                cur_off += 4
            if ok:
                branches.append(And(*cons))
        # at least one candidate must be true
        s.add(Or(*branches))
        off += 41

    print(f"[*] Total bit constraints cover {off} bits; Z3 variables: {len(st)} state words + {len(outs)} outs")

    ok = s.check()
    if ok != sat:
        raise RuntimeError("Z3 unsat — try more samples or raise budgets.")
    m = s.model()

    # materialize concrete outputs so we can slice raw bits later
    out_words = [m.evaluate(outs[i]).as_long() for i in range(len(outs))]
    return out_words

# ---------------------------
# Networking + orchestration
# ---------------------------

def recv_until(sock, end=b"\n"):
    data = b""
    while not data.endswith(end):
        ch = sock.recv(1)
        if not ch:
            break
        data += ch
    return data

def get_scramble(sock) -> str:
    sock.sendall(b"1\n")
    line = recv_until(sock, b"\n")
    return line.decode().strip()

def get_flagline(sock) -> str:
    sock.sendall(b"2\n")
    line = recv_until(sock, b"\n")
    return line.decode().strip()

def simulate_g_from_bits(bitstream: List[int], start_bit: int, length: int) -> List[int]:
    """ Reproduce PRNG.g(l): n(False) once (5 bits, %18), then n(True) for rest (4 bits each with sector offset). """
    # helper to read n bits MSB-first from bitstream (list of 32-bit ints)
    def readbits(off, n):
        res = 0
        for i in range(n):
            widx = (off + i) // 32
            bidx = (off + i) % 32
            # MSB-first in each 32-bit word
            bit = (bitstream[widx] >> (31 - bidx)) & 1
            res = (res << 1) | bit
        return res

    moves = []
    off = start_bit
    # first move
    x = readbits(off, 5); off += 5
    m0 = x % 18
    moves.append(m0)
    prev = m0
    # rest
    for _ in range(length-1):
        q = readbits(off, 4); off += 4
        r = q % 12
        base = ((prev // 6) + 1) * 6
        m = (base + r) % 18
        moves.append(m)
        prev = m
    return moves

def invert_moves(moves: List[int]) -> List[int]:
    return [INV[m] for m in moves[::-1]]

# Tunables
TARGET_SAMPLES = 150            # số lần bấm "1" để gom mẫu (120–200 tuỳ máy)
WORDS_BUDGET   = 6000           # số word 32-bit sinh trong Z3 (dư chút)
CAP_CANDIDATES_PER_RUN = None   # đặt số (ví dụ 8000) nếu RAM yếu

def main():
    global FWD5
    print("[*] Precomputing forward depth=5 states (this may take a while)...")
    FWD5 = gen_forward(5)
    print(f"[*] Forward map states: {len(FWD5)}")

    print(f"[*] Connecting to {HOST}:{PORT} ...")
    s = socket.create_connection((HOST, PORT))

    runs: List[Run] = []
    bit_off = 0
    for i in range(TARGET_SAMPLES):
        out = get_scramble(s)
        if not out:
            print("[!] connection closed early"); sys.exit(1)
        print(f"[{i+1}/{TARGET_SAMPLES}] got len={len(out)}  head={out[:24]}...")

        cands = enumerate_len10(out)
        if CAP_CANDIDATES_PER_RUN and len(cands) > CAP_CANDIDATES_PER_RUN:
            cands = cands[:CAP_CANDIDATES_PER_RUN]
            print(f"    [+] candidates: {len(cands)} (capped)")
        else:
            print(f"    [+] candidates: {len(cands)}")

        runs.append(Run(out=out, cands=cands))
        bit_off += 41

    print("[*] Building + solving MT19937 constraints ...")
    outs = solve_mt_from_runs(runs, words_budget=WORDS_BUDGET)
    print("[+] MT state recovered (via outs).")

    # predict g(100) starting right after our last sample bits
    start_bits = TARGET_SAMPLES * 41
    words_needed = (start_bits + 401 + 31) // 32
    if len(outs) < words_needed:
        print("[!] Not enough outs words; raise WORDS_BUDGET"); sys.exit(1)

    predicted_moves = simulate_g_from_bits(outs, start_bits, 100)
    inv_moves = invert_moves(predicted_moves)

    # ask server for the scrambled flag line, then unshuffle locally
    scrambled = get_flagline(s)
    print(f"[+] got scrambled flag (len={len(scrambled)}): {scrambled[:32]}...")

    cube = cubify(scrambled)
    # apply inverse
    for m in inv_moves:
        CALLER[m](cube)
    plain = linify(cube)
    flag = "LITCTF{" + plain + "}"
    print("\n==== FLAG ====")
    print(flag)
    print("==============")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] aborted")