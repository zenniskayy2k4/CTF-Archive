#!/usr/bin/env python3
# rev_debug.py
# Improved translation + diagnostic + linear-fit to match expected encoded numbers.
# Usage: python3 rev_debug.py [FLAG]
# If you have a partial/complete EXPECTED list, put it into EXPECTED_PARTIAL below.

import sys
from typing import List
import math

# ---------------------------
# Put your expected numbers here (partial or full), as integers.
# Example (from your message) — replace/extend with the full expected list if you have it:
EXPECTED_PARTIAL = [
    16517,16658,16546,16533,16553,16553,16650,16546,16521,16970,16970,16970
]

# ---------------------------
# Helper array utils
def rotate_right(xs: List[int], k: int) -> List[int]:
    if not xs: return xs
    k = k % len(xs)
    return xs[-k:] + xs[:-k]

def chunks(xs: List[int], size: int) -> List[List[int]]:
    return [xs[i:i+size] for i in range(0, len(xs), size)]

# ---------------------------
# Best-effort implementations of A, L, E, P (improved & deterministic)
def A(x: int, y: int) -> int:
    # element-wise mixing using small bitops to get varied, but stable values
    diff = x - y
    ad = abs(diff)
    ge = 1 if x >= y else 0
    # mixing: diff, parity, low bits of product
    mix = ((x * y) & 0xFF) ^ ((x ^ y) & 0x7F)
    return (ad & 0x3FF) + ge*5 + (mix & 0x1F)

def L(seq: List[int]) -> List[int]:
    # sliding 3-window cyclic sum (keeps values small/regular)
    n = len(seq)
    if n == 0:
        return []
    out = []
    for i in range(n):
        w = seq[(i-1) % n] + seq[i] + seq[(i+1) % n]
        out.append(w)
    return out

def E(seq: List[int]) -> List[int]:
    # map A to cyclic neighbor pairs -> filter positives -> L aggregate
    if not seq:
        return []
    mapped = [A(seq[i], seq[(i+1) % len(seq)]) for i in range(len(seq))]
    filtered = [v for v in mapped if v > 0]
    return L(filtered)

def P(seq: List[int]) -> List[int]:
    # alternating prefix sum pattern + small modulus shift
    if not seq:
        return []
    acc = 0
    out = []
    for i,v in enumerate(seq):
        acc += v if (i % 2 == 0) else -v
        out.append(abs(acc) % 1024 + 100)  # offset to avoid very small numbers
    return out

# Combine (used only for producing final outputs before fitting)
def C_combine(e: List[int], p: List[int], base:int=16500, a:int=1, b:int=1, c:int=0, d:int=0) -> List[int]:
    # base + a*e + b*p + c*pos + d*ord
    n = max(len(e), len(p))
    if n == 0:
        return []
    e_ext = (e * ((n // len(e)) + 1))[:n] if e else [0]*n
    p_ext = (p * ((n // len(p)) + 1))[:n] if p else [0]*n
    return [ base + a*e_ext[i] + b*p_ext[i] + c*(i) + d*0 for i in range(n) ]

# ---------------------------
# Small linear algebra (solve (X^T X) w = X^T y)
def transpose(M):
    return list(map(list, zip(*M))) if M else []

def mat_mul(A,B):
    # A: m x k, B: k x n -> m x n
    m = len(A); k = len(A[0]) if m else 0
    n = len(B[0]) if B else 0
    C = [[0.0]*n for _ in range(m)]
    for i in range(m):
        for j in range(n):
            s = 0.0
            for t in range(k):
                s += A[i][t]*B[t][j]
            C[i][j] = s
    return C

def mat_vec_mul(A, v):
    return [ sum(A[i][j]*v[j] for j in range(len(v))) for i in range(len(A)) ]

def solve_linear_system(A: List[List[float]], b: List[float]) -> List[float]:
    # Gaussian elimination with partial pivoting
    n = len(b)
    # build augmented matrix
    M = [ [float(A[i][j]) for j in range(n)] + [float(b[i])] for i in range(n) ]
    for i in range(n):
        # pivot
        pivot_row = max(range(i,n), key=lambda r: abs(M[r][i]))
        if abs(M[pivot_row][i]) < 1e-12:
            # singular or nearly so; regularize
            M[i][i] += 1e-8
        if pivot_row != i:
            M[i], M[pivot_row] = M[pivot_row], M[i]
        # normalize row
        piv = M[i][i]
        if abs(piv) < 1e-12:
            continue
        for j in range(i, n+1):
            M[i][j] /= piv
        # eliminate others
        for r in range(n):
            if r == i: continue
            factor = M[r][i]
            if abs(factor) < 1e-15: continue
            for j in range(i, n+1):
                M[r][j] -= factor * M[i][j]
    # read solution
    x = [ M[i][n] for i in range(n) ]
    return x

# ---------------------------
def fit_and_predict(flag: str, expected_partial: List[int]):
    # build base sequence
    seq = [ (ord(ch) + i*3) & 0xFFFF for i,ch in enumerate(flag) ]
    e = E(seq)
    p = P(seq)

    n_fit = min(len(expected_partial), len(seq))
    # build design matrix X of size n_fit x p
    X = []
    y = []
    for i in range(n_fit):
        Ei = e[i % len(e)] if e else 0
        Pi = p[i % len(p)] if p else 0
        pos = i
        ordv = ord(flag[i])
        X.append([1.0, float(Ei), float(Pi), float(pos), float(ordv)])
        y.append(float(expected_partial[i]))

    # compute normal eq: (X^T X) w = X^T y
    Xt = transpose(X)  # p x n
    XtX = mat_mul(Xt, X)  # p x p
    Xty = mat_vec_mul(Xt, y)  # p
    # regularize small diagonal to avoid singular
    for i in range(len(XtX)):
        XtX[i][i] += 1e-8

    w = solve_linear_system(XtX, Xty)  # coefficients
    # predict for full flag length
    preds = []
    for i in range(len(seq)):
        Ei = e[i % len(e)] if e else 0
        Pi = p[i % len(p)] if p else 0
        pos = i
        ordv = ord(flag[i])
        pred = w[0] + w[1]*Ei + w[2]*Pi + w[3]*pos + w[4]*ordv
        preds.append(int(round(pred)))

    # compute residuals for the partial positions
    residuals = [ (expected_partial[i] - (w[0] + w[1]* (e[i%len(e)] if e else 0) + w[2]* (p[i%len(p)] if p else 0) + w[3]*i + w[4]*ord(flag[i])) )
                  for i in range(n_fit) ]

    return {
        "seq": seq,
        "E": e,
        "P": p,
        "weights": w,
        "preds": preds,
        "residuals_partial": residuals,
    }

# ---------------------------
if __name__ == "__main__":
    Flag = sys.argv[1] if len(sys.argv) > 1 else "brunner{...}"
    print("Flag used:", Flag)
    if EXPECTED_PARTIAL:
        print("Using EXPECTED_PARTIAL (len={}):".format(len(EXPECTED_PARTIAL)))
        print(EXPECTED_PARTIAL)
    print("--- computing ---")
    R = fit_and_predict(Flag, EXPECTED_PARTIAL)

    # show small debug
    print("\nseq (first 20):", R["seq"][:20])
    print("E   (first 20):", R["E"][:20])
    print("P   (first 20):", R["P"][:20])
    print("\nLearned linear weights (b0, bE, bP, bPos, bOrd):")
    print([ round(x,6) for x in R["weights"] ])
    print("\nResiduals on provided expected partial (should be close to 0):")
    print([ round(r,6) for r in R["residuals_partial"] ])
    # full predicted dotted string
    dot_string = ".".join(str(x) for x in R["preds"])
    print("\nPredicted full output (quoted):")
    print(f"\"{dot_string}\"")

    # also print the prefix corresponding to expected partial
    prefix_pred = ".".join(str(R["preds"][i]) for i in range(min(len(R["preds"]), len(EXPECTED_PARTIAL))))
    print("\nPredicted prefix for expected-partial positions:")
    print(f"\"{prefix_pred}\"")

    print("\nIf residuals are non-zero, try:")
    print("- Provide a longer EXPECTED_PARTIAL (more data -> better fit).")
    print("- Paste actual Uiua program's output for a small test flag (e.g. 'A' or 'abc') so we can compare internal E/P.")
