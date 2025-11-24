#!/usr/bin/env python3
# solve_parallel.py
# Brute-force (s,t) với multiprocessing, resume, log
# WARNING: có thể tốn thời gian. Điều chỉnh S_MAX, T_MAX, N_PROCS.

from pwn import remote
from Crypto.Util.number import long_to_bytes
from sympy import symbols, Poly, gcd
import multiprocessing as mp
import time
import os
import sys

HOST = "52.59.124.14"
PORT = 5101
E = 3

# Tune these
S_MAX = 1 << 16      # số s thử (ví dụ 65536)
T_MAX = 1 << 12      # số t thử (ví dụ 4096)
N_PROCS = max(1, mp.cpu_count() - 1)
CHUNK = 256          # mỗi process xử lý CHUNK giá trị của s/lần
CHECKPOINT = "pkcs_checkpoint.txt"

def get_server_data():
    io = remote(HOST, PORT)
    data = io.recvall(timeout=5)
    io.close()
    if not data:
        raise RuntimeError("Không nhận được dữ liệu từ server.")
    text = data.decode(errors='ignore').strip()
    return text

def parse_server(text):
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    lflag = int(lines[0])
    n = int(lines[1])
    c1 = int(lines[2], 16)
    c2 = int(lines[3], 16)
    return lflag, n, c1, c2

def try_franklin_reiter(n, e, c1, c2, a, b):
    x = symbols('x')
    f1 = Poly((x + a)**e - int(c1 % n), x, modulus=n)
    f2 = Poly((x + b)**e - int(c2 % n), x, modulus=n)
    g = gcd(f1, f2)
    if g.is_zero:
        return None
    deg = g.degree()
    if deg == 1:
        coeffs = g.all_coeffs()
        A = int(coeffs[0]) % n
        B = int(coeffs[1]) % n
        try:
            invA = pow(A, -1, n)
        except ValueError:
            return None
        root = (-B * invA) % n
        return int(root)
    return None

def extract_flag(m_int, lflag):
    b = long_to_bytes(m_int)
    if b.count(b'\x00') == 0:
        return None
    idx = b.rfind(b'\x00')
    candidate = b[idx+1:]
    if len(candidate) != lflag:
        if len(candidate) < lflag:
            candidate = (b'\x00'*(lflag - len(candidate))) + candidate
        else:
            candidate = candidate[-lflag:]
    return candidate

def worker(task):
    """task: (start_s, end_s, n, e, c1, c2, R, lflag)"""
    start_s, end_s, n, e, c1, c2, R, lflag = task
    total = (end_s - start_s) * (T_MAX)
    cnt = 0
    for s in range(start_s, end_s):
        a_base = (s * R) % n
        for t in range(1, T_MAX):
            b_base = ((s + t) * R) % n
            cnt += 1
            if cnt % 5000 == 0:
                print(f"[PID {os.getpid()}] s={s} t={t} attempts={cnt}")
            try:
                root = try_franklin_reiter(n, e, c1, c2, a_base, b_base)
            except Exception:
                root = None
            if root is not None:
                flag = extract_flag(root, lflag)
                return (True, s, t, root, flag)
    return (False, None, None, None, None)

def main():
    print("[*] Lấy dữ liệu server...")
    text = get_server_data()
    lflag, n, c1, c2 = parse_server(text)
    print(f"[+] len={lflag}, n bits={n.bit_length()}, c1.. c2..")
    R = pow(256, lflag)
    print(f"[*] R bitlen = {R.bit_length()}")

    # Build tasks: chia S_MAX thành CHUNK-block
    tasks = []
    for s0 in range(0, S_MAX, CHUNK):
        s1 = min(S_MAX, s0 + CHUNK)
        tasks.append((s0, s1, n, E, c1, c2, R, lflag))

    print(f"[*] N_TASKS = {len(tasks)}, N_PROCS = {N_PROCS}")
    pool = mp.Pool(N_PROCS)
    try:
        for i, res in enumerate(pool.imap_unordered(worker, tasks)):
            found, s, t, root, flag = res
            if found:
                print("[+] FOUND! s=", s, "t=", t)
                print("[+] m =", root)
                if flag:
                    try:
                        print("[+] flag:", flag.decode())
                    except:
                        print("[+] flag bytes (hex):", flag.hex())
                pool.terminate()
                return
            if (i+1) % 10 == 0:
                print(f"[*] Completed {i+1}/{len(tasks)} tasks")
    except KeyboardInterrupt:
        print("[!] Interrupted by user")
    finally:
        pool.terminate()
        pool.join()
    print("[-] Done, no result. Increase S_MAX/T_MAX or switch strategy.")

if __name__ == "__main__":
    main()
