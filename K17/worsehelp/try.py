#!/usr/bin/env python3
"""
farm_worsehelp.py

Tool tự động farm output từ server worsehelp.
Sinh a,b -> gửi tới server -> thu c,e,n.
Lưu tất cả vào file JSON. Highlight nếu e == 1 hoặc e nhỏ.
"""

import socket
import json
import time
from Crypto.Util.number import getPrime, isPrime

HOST = "challenge.secso.cc"
PORT = 7008
OUTFILE = "farm_results.json"

def ensure_composite(x):
    if not isPrime(x):
        return x
    return x * getPrime(32)

def gen_candidates(a, bits=1024):
    """Sinh một số b candidate có cấu trúc."""
    cands = []
    # b = a + t
    for t in [-3,-2,-1,0,1,2,3,7,11]:
        b = a + t
        if b.bit_length() < bits:
            b = b * getPrime(bits - b.bit_length() + 16)
        b = ensure_composite(b)
        cands.append((f"a_plus_{t}", b))

    # b = k*a
    for k in [2,3,4,5,7,11]:
        b = a * k
        if b.bit_length() < bits:
            b = b * getPrime(bits - b.bit_length() + 16)
        b = ensure_composite(b)
        cands.append((f"{k}_times_a", b))

    # b = random product of two 512-bit primes
    p = getPrime(bits//2)
    q = getPrime(bits//2)
    b = ensure_composite(p*q)
    cands.append(("prod_512_512", b))

    return cands

def send_and_receive(a, b, host=HOST, port=PORT, timeout=5.0):
    payload = f"{a},{b}\n".encode()
    try:
        s = socket.create_connection((host, port), timeout=10)
    except Exception as e:
        return {"error": f"connect: {e}"}
    try:
        s.settimeout(1.0)
        banner = b""
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                banner += chunk
        except Exception:
            pass

        s.sendall(payload)

        s.settimeout(timeout)
        resp = b""
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                resp += chunk
        except Exception:
            pass
        return {"banner": banner.decode(errors="ignore"),
                "resp": resp.decode(errors="ignore")}
    finally:
        s.close()

def parse_response(resp_str):
    """Parse server response để lấy c,e,n nếu có."""
    out = {}
    for line in resp_str.splitlines():
        if line.startswith("c ="):
            out["c"] = line.split("=",1)[1].strip()
        elif line.startswith("e ="):
            out["e"] = line.split("=",1)[1].strip()
        elif line.startswith("n ="):
            out["n"] = line.split("=",1)[1].strip()
    return out

def main():
    results = []
    a = getPrime(1024)
    print(f"[+] Generated a (bitlen={a.bit_length()})")

    cands = gen_candidates(a)
    print(f"[*] {len(cands)} candidates generated")

    for idx, (name, b) in enumerate(cands,1):
        print(f"[{idx}/{len(cands)}] Trying {name}...")
        res = send_and_receive(a,b)
        if "resp" not in res:
            print("  [!] Error:", res.get("error","no response"))
            continue
        parsed = parse_response(res["resp"])
        entry = {"a": str(a), "b": str(b), "name": name}
        entry.update(parsed)
        results.append(entry)

        if "e" in parsed:
            try:
                e_val = int(parsed["e"])
                if e_val == 1:
                    print("  [!!!] Found e=1 -> ciphertext is the flag!")
                elif e_val < 10000:
                    print(f"  [!] Found small e = {e_val}")
            except: pass

        time.sleep(1)

    with open(OUTFILE,"w") as f:
        json.dump(results,f,indent=2)
    print(f"[+] Saved {len(results)} results to {OUTFILE}")

if __name__ == "__main__":
    main()
