#!/usr/bin/env python3
"""
Brute-force runner for pointless.hs checkFlag.

Usage:
    1) Put pointless.hs in same folder.
    2) python3 bf_check.py

What it does:
    - Tries to compile pointless.hs to ./pointless_bin using ghc -O2 (if ghc present).
    - If compile fails or ghc missing, falls back to runhaskell pointless.hs for each test.
    - Generates candidates of form: watctf{PAYLOAD}
    - PAYLOAD characters and length range are configurable below.
    - Uses multiprocessing to parallelize checks.
"""
import subprocess, sys, os, itertools, time
from multiprocessing import Pool, cpu_count, Manager

# ---------- Configuration ----------
HS_FILE = "chall.hs"         # your Haskell file
BIN = "./pointless_bin"          # compiled binary name
USE_COMPILE = True               # try to compile first (recommended)
NPROCS = max(1, cpu_count() - 1) # processes to use
# characters inside braces (payload). adjust if needed.
CHARS = "abcdefghijklmnopqrstuvwxyz0123456789_-" 
MIN_PAYLOAD = 6   # minimum length inside braces
MAX_PAYLOAD = 12  # maximum length inside braces (increase if you want but exponential)
BATCH_SIZE = 200  # number of candidates per process submit (tunes throughput)
# -----------------------------------

def try_compile():
    if not USE_COMPILE:
        return False
    if not os.path.exists(HS_FILE):
        print("Error: cannot find", HS_FILE)
        return False
    print("Attempting to compile", HS_FILE, "with ghc ...")
    try:
        p = subprocess.run(["ghc", "-O2", HS_FILE, "-o", BIN], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
    except FileNotFoundError:
        print("ghc not found on PATH. Will use runhaskell fallback.")
        return False
    if p.returncode == 0:
        print("Compiled to", BIN)
        return True
    else:
        print("Compilation failed; will fallback to runhaskell.")
        print(p.stderr.decode(errors="ignore"))
        return False

def check_candidate_with_bin(candidate):
    """Run compiled binary; feed candidate on stdin; parse output."""
    try:
        p = subprocess.run([BIN], input=(candidate+"\n").encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
    except Exception as e:
        return False, "err"
    out = p.stdout.decode(errors="ignore")
    # program prints "Correct" or "Wrong"
    if "Correct" in out:
        return True, out
    return False, out

def check_candidate_with_runhaskell(candidate):
    """Run runhaskell with file each time (slower)."""
    try:
        p = subprocess.run(["runhaskell", HS_FILE], input=(candidate+"\n").encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=8)
    except FileNotFoundError:
        return False, "runhaskell-not-found"
    except Exception as e:
        return False, "err"
    out = p.stdout.decode(errors="ignore")
    if "Correct" in out:
        return True, out
    return False, out

# Choose runner dynamically
USE_BIN = False
if try_compile():
    USE_BIN = True
else:
    # If no compile, ensure runhaskell exists when used later; we'll try on-demand
    USE_BIN = False

def worker_batch(candidates):
    """Worker receives list of candidates; returns first success or None."""
    for cand in candidates:
        if USE_BIN:
            ok, out = check_candidate_with_bin(cand)
        else:
            ok, out = check_candidate_with_runhaskell(cand)
        if ok:
            return cand, out
    return None

def chunked_iterable(iterable, size):
    it = iter(iterable)
    while True:
        chunk = list(itertools.islice(it, size))
        if not chunk:
            break
        yield chunk

def candidate_generator():
    prefix = "watctf{"
    suffix = "}"
    # iterate payload lengths from MIN_PAYLOAD to MAX_PAYLOAD
    for L in range(MIN_PAYLOAD, MAX_PAYLOAD+1):
        # product yields tuples of characters
        for prod in itertools.product(CHARS, repeat=L):
            payload = "".join(prod)
            yield prefix + payload + suffix

def main():
    start = time.time()
    print(f"Brute force starting: chars={len(CHARS)} payload_len={MIN_PAYLOAD}..{MAX_PAYLOAD}, procs={NPROCS}")
    gen = candidate_generator()
    pool = Pool(NPROCS)
    manager = Manager()
    futures = []
    total_tested = 0
    try:
        for batch in chunked_iterable(gen, BATCH_SIZE):
            total_tested += len(batch)
            # map asynchronously
            res = pool.apply_async(worker_batch, (batch,))
            futures.append(res)
            # clean finished futures occasionally
            new_futures = []
            for f in futures:
                if f.ready():
                    ans = f.get()
                    if ans is not None:
                        cand, out = ans
                        print("\n=== FOUND FLAG ===")
                        print(cand)
                        print("Program output:\n", out)
                        pool.terminate()
                        pool.join()
                        return
                else:
                    new_futures.append(f)
            futures = new_futures
            # small status
            if total_tested % (BATCH_SIZE*50) == 0:
                elapsed = time.time() - start
                print(f"Tested ~{total_tested} candidates, elapsed {int(elapsed)}s")
        # finish remaining futures
        for f in futures:
            if f.ready():
                ans = f.get()
                if ans is not None:
                    cand, out = ans
                    print("\n=== FOUND FLAG ===")
                    print(cand)
                    print("Program output:\n", out)
                    pool.terminate()
                    pool.join()
                    return
        print("Finished search (no result).")
    except KeyboardInterrupt:
        print("Interrupted by user.")
    finally:
        pool.terminate()
        pool.join()
    elapsed = time.time() - start
    print("Done. Tested ~", total_tested, "candidates in", int(elapsed), "s")

if __name__ == "__main__":
    main()
