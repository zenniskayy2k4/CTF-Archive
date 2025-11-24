#!/usr/bin/env python3
# brute_libc.py
# Bruteforce seeds for "Numbers Game" using glibc rand/srand (via ctypes).
# Usage examples:
#  python3 brute_libc.py           # default ±3600s window, 50 threads
#  python3 brute_libc.py --window 7200 --threads 80
#  python3 brute_libc.py --start 1759000000 --end 1759050000 --threads 40

import ctypes, socket, time, argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading, sys

HOST_DEFAULT = 'chal.sunshinectf.games'
PORT_DEFAULT = 25101
EXPECT_BANNER = b"Hint:"   # wait for banner that contains this before sending

stop_event = threading.Event()

def get_libc():
    for name in ("libc.so.6","libc.so"):
        try:
            lib = ctypes.CDLL(name)
            # set prototypes
            lib.srand.argtypes = [ctypes.c_uint]
            lib.rand.restype = ctypes.c_int
            return lib
        except Exception:
            pass
    raise RuntimeError("libc not found. Run on Linux/WSL with libc.so.6 available.")

def compute_guess_for_seed(libc, seed):
    # IMPORTANT: this function should only be called from the main thread
    # (we will precompute all guesses serially to avoid race on srand/rand)
    libc.srand(ctypes.c_uint(seed))
    r1 = libc.rand() & 0xffffffff
    r2 = libc.rand() & 0xffffffff
    r3 = libc.rand() & 0xffffffff
    guess = (r1 | ((r2 & 0xffffffff) << 31) | ((r3 & 0xffffffff) << 62)) & ((1<<64)-1)
    return guess

def wait_for_banner(sock, timeout=2.0, expect=EXPECT_BANNER):
    # read from socket until 'expect' appears or timeout
    sock.settimeout(0.5)
    data = b""
    end = time.time() + timeout
    while time.time() < end:
        try:
            part = sock.recv(4096)
            if not part:
                break
            data += part
            if expect in data:
                return data
        except socket.timeout:
            # no data right now, loop again until timeout
            continue
        except Exception:
            break
    return data

def send_guess_and_check(host, port, seed, guess, banner_wait=2.0, resp_timeout=4.0):
    if stop_event.is_set():
        return None
    try:
        s = socket.socket()
        s.settimeout(4)
        s.connect((host, port))
    except Exception as e:
        return None

    try:
        banner = wait_for_banner(s, timeout=banner_wait)
        # If banner is empty, we still proceed but it's risky; we prefer to only send if we saw expect
        if EXPECT_BANNER not in banner and len(banner) < 5:
            # didn't see banner properly — safer to bail this attempt
            s.close()
            return None

        # send guess
        s.sendall(str(guess).encode() + b"\n")

        # read full response
        s.settimeout(0.5)
        full = banner  # keep received banner
        end = time.time() + resp_timeout
        while time.time() < end:
            try:
                part = s.recv(4096)
                if not part:
                    break
                full += part
            except socket.timeout:
                continue
            except Exception:
                break

        text = full.decode(errors='ignore')
        # If response doesn't contain WRONG, it's likely the winning response (or an error)
        if "WRONG" not in text and "Error" not in text:
            # Found candidate — set global event to stop other workers
            stop_event.set()
            return (seed, guess, text)
    finally:
        try:
            s.close()
        except:
            pass
    return None

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default=HOST_DEFAULT)
    parser.add_argument("--port", type=int, default=PORT_DEFAULT)
    parser.add_argument("--window", type=int, default=3600,
                        help="±seconds around now to brute (default 3600)")
    parser.add_argument("--threads", type=int, default=50, help="number of parallel connections")
    parser.add_argument("--start", type=int, default=None, help="start timestamp (overrides window)")
    parser.add_argument("--end", type=int, default=None, help="end timestamp (overrides window)")
    parser.add_argument("--banner-wait", type=float, default=2.0, help="secs to wait to receive full banner")
    parser.add_argument("--resp-timeout", type=float, default=4.0, help="secs to wait for full response after sending")
    args = parser.parse_args()

    libc = get_libc()
    # build seed range
    if args.start is not None and args.end is not None:
        start_ts = args.start
        end_ts = args.end
    else:
        now = int(time.time())
        start_ts = now - args.window
        end_ts = now + args.window

    print(f"[+] Host: {args.host}:{args.port}")
    print(f"[+] Seeds: {start_ts} .. {end_ts} (total {end_ts - start_ts + 1})")
    print("[+] Precomputing guesses (this uses libc.srand/rand — done single-threaded)...")

    seeds = list(range(start_ts, end_ts + 1))
    guesses = []
    total = len(seeds)
    for i, s_ts in enumerate(seeds, 1):
        g = compute_guess_for_seed(libc, s_ts)
        guesses.append((s_ts, g))
        if i % 500 == 0 or i == total:
            print(f"    precomputed {i}/{total}")

    print("[+] Precompute done. Launching parallel attempts...")
    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        futures = { ex.submit(send_guess_and_check, args.host, args.port, seed, guess, args.banner_wait, args.resp_timeout): (seed, guess)
                   for seed, guess in guesses }
        try:
            for fut in as_completed(futures):
                result = fut.result()
                if result:
                    seed, guess, text = result
                    print("\n[+] POSSIBLE FLAG RESPONSE FOUND!")
                    print(f"    seed = {seed}")
                    print(f"    guess = {guess}")
                    print("---- response ----")
                    print(text)
                    print("------------------")
                    return
                if stop_event.is_set():
                    break
        except KeyboardInterrupt:
            print("Interrupted by user, shutting down.")
            stop_event.set()

    print("[!] Done. No candidate found in range (or all attempts returned WRONG). Try increasing the window or threads.")

if __name__ == "__main__":
    main()
