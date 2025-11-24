#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# recover_flag.py - giải bài "Beta Bet" 07CTF
#
# Cách chạy:
#   python recover_flag.py out.txt
#
# out.txt là file chứa 113 dòng ciphertext mà đề in ra.
#

import sys
from itertools import product

PREFIX = "07CTF{"
SUFFIX = "}"

def load_cts(path):
    lines = []
    with open(path, "r", encoding="utf-8") as f:
        for ln in f:
            ln = ln.strip()
            if not ln:
                continue
            if ln.startswith(PREFIX) and ln.endswith(SUFFIX):
                mid = ln[len(PREFIX):-len(SUFFIX)]
                lines.append(mid)
            else:
                # fallback: lấy giữa { và }
                if "{" in ln and "}" in ln:
                    l = ln.find("{")
                    r = ln.rfind("}")
                    lines.append(ln[l+1:r])
                else:
                    lines.append(ln)
    return lines

def char_to_val(ch): return ord(ch) - ord('a')
def val_to_char(v): return chr((v % 26) + ord('a'))

def possible_chars_at_pos(cts, pos):
    # tính những chữ cái plaintext hợp lệ tại vị trí pos
    forbidden = set()
    for c in cts:
        cv = char_to_val(c[pos])
        # key = (c - p - 12) mod26 != 0  => p != (c - 12) mod26
        forbidden.add((cv - 12) % 26)
    allowed = [val_to_char(p) for p in range(26) if p not in forbidden]
    return allowed

def main(path):
    mids = load_cts(path)
    if not mids:
        print("Không đọc được ciphertext nào.")
        return
    L = len(mids[0])
    print(f"Loaded {len(mids)} ciphertext samples, length = {L}")

    candidates_per_pos = []
    for pos in range(L):
        allowed = possible_chars_at_pos(mids, pos)
        candidates_per_pos.append(allowed)
        print(f"pos {pos}: allowed={allowed}")

    # tính tổng số tổ hợp
    total = 1
    for opts in candidates_per_pos:
        total *= len(opts)
    print(f"\nTổng số tổ hợp có thể: {total}")

    # nếu ít (ví dụ < 100000), thử hết
    MAX_COMBOS = 200000
    if total <= MAX_COMBOS:
        words = ["thought","learning","learn","from","enigma",
                 "would","make","more","secure","security"]
        def score(s):
            sc = 0
            for w in words:
                if w in s:
                    sc += len(w)
            return sc

        best = None
        best_score = -1
        for combo in product(*candidates_per_pos):
            inner = "".join(combo)
            sc = score(inner)
            if sc > best_score:
                best = inner
                best_score = sc
        flag = f"{PREFIX}{best}{SUFFIX}"
        print("\n==> Recovered flag:")
        print(flag)
    else:
        # nếu tổ hợp quá lớn thì chỉ in greedy guess
        greedy = "".join(opts[0] if opts else "?" for opts in candidates_per_pos)
        flag = f"{PREFIX}{greedy}{SUFFIX}"
        print("\nQuá nhiều tổ hợp, in greedy guess:")
        print(flag)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python recover_flag.py out.txt")
        sys.exit(1)
    main(sys.argv[1])
