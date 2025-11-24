#!/usr/bin/env python3
# solve_auto.py - fully automatic version for "A slice of keys"

import sys, time, random
from math import gcd
from pwn import remote
from Crypto.Cipher import AES

HOST = "52.59.124.14"
PORT = 5103
TIMEOUT = 12

BASES_PER_ROUND = 20
CONFIRM_BASES = 20
TOP_BITS_TO_RECOVER = 300   # >= 258
AUTO_ACCEPT_THRESHOLD = 0.8
AUTO_REJECT_THRESHOLD = 0.2

def pow_2exp(base, t, n):
    v = base % n
    for _ in range(t):
        v = (v * v) % n
    return v

class RSAOracle:
    def __init__(self, host, port, timeout=TIMEOUT):
        self.host = host; self.port = port; self.timeout = timeout
        self.connect()

    def connect(self):
        self.r = remote(self.host, self.port, timeout=self.timeout)
        self.cipher_hex = None
        self.banner = []
        for _ in range(12):
            line = self.r.recvline(timeout=self.timeout)
            if not line:
                break
            s = line.strip().decode(errors='ignore')
            if s:
                self.banner.append(s)
                if all(c in "0123456789abcdefABCDEF" for c in s) and len(s) % 2 == 0:
                    self.cipher_hex = s
                    break
        if not self.cipher_hex:
            raise RuntimeError("Couldn't find cipher hex in banner: " + repr(self.banner))
        self.cipher = bytes.fromhex(self.cipher_hex)
        self.queries = 0

    def close(self):
        try: self.r.close()
        except: pass

    def _recv_result_line(self):
        for _ in range(400):
            line = self.r.recvline(timeout=self.timeout)
            if line is None:
                raise RuntimeError("no response")
            s = line.strip().decode(errors='ignore')
            if s == "":
                continue
            if all(c in "0123456789-" for c in s):
                return s
        raise RuntimeError("No numeric response seen")

    def _send_and_recv_num(self, line):
        self.r.sendline(line.encode())
        self.queries += 1
        return int(self._recv_result_line())

    def enc(self, m:int) -> int:
        return self._send_and_recv_num(f"e:{m}")

    def dec(self, m:int) -> int:
        return self._send_and_recv_num(f"d:{m}")

# --- recover modulus n ---
def recover_modulus_n(oracle, e=1337, trials=18):
    collected = []
    for i in range(trials):
        a = random.getrandbits(128) | 3
        A = oracle.enc(a)
        diff = pow(a, e) - A
        collected.append(abs(diff))
        g = collected[0]
        for v in collected[1:]:
            g = gcd(g, v)
        if g > 1 and g.bit_length() > 100:
            ok = True
            for _ in range(3):
                t = random.getrandbits(64) | 2
                if oracle.enc(t) != pow(t, e, g):
                    ok = False; break
            if ok:
                return g
    raise RuntimeError("Failed to recover n via gcd trick")

# --- per-bit vote ---
def vote_on_candidate(oracle, n, pref_len, candidate_int, B, bases_count=BASES_PER_ROUND):
    t_small = B - pref_len - 1
    votes = 0; total = 0
    for _ in range(bases_count):
        g = random.randrange(3, n-2) | 1
        try:
            G = pow_2exp(g, t_small, n)
            DG = oracle.dec(G)
            S = pow_2exp(g, t_small + pref_len, n)
            DS = oracle.dec(S)
        except Exception:
            continue
        base2 = pow_2exp(g, t_small, n)
        factor = pow(base2, candidate_int, n)
        inv_factor = pow(factor, -1, n)
        rem = (DG * inv_factor) % n
        pred = 1 if rem == DS else 0
        if pred == 1:
            votes += 1
        total += 1
    return votes, total

def confirm_on_new_connection(n, candidate_len, candidate_int, B, confirm_bases=CONFIRM_BASES):
    oracle2 = RSAOracle(HOST, PORT, timeout=TIMEOUT)
    try:
        v, t = vote_on_candidate(oracle2, n, candidate_len, candidate_int, B, bases_count=confirm_bases)
    finally:
        oracle2.close()
    return v, t

def auto_recover(oracle, n, B=TOP_BITS_TO_RECOVER, want_bits=128):
    if B < 258:
        raise ValueError("B must be >= 258")
    L = n.bit_length()
    print(f"[info] n bitlen ~ {L}. Will recover top {B} bits (MSB-first).")
    prefix_int = 0; prefix_len = 0
    while prefix_len < B:
        decided = False
        for bit in (0,1):
            cand = (prefix_int << 1) | bit
            cand_len = prefix_len + 1
            v, t = vote_on_candidate(oracle, n, cand_len, cand, B, bases_count=BASES_PER_ROUND)
            frac = v/t if t>0 else 0.0
            print(f"[bit {cand_len}] trying {bit}: votes {v}/{t} frac={frac:.2f}")
            if t==0:
                continue
            if frac >= AUTO_ACCEPT_THRESHOLD:
                print("  auto-accept bit", bit)
                prefix_int = cand; prefix_len = cand_len; decided=True; break
            if frac <= AUTO_REJECT_THRESHOLD:
                print("  auto-reject bit", bit)
                continue
            # ambiguous → confirm
            v2, t2 = confirm_on_new_connection(n, cand_len, cand, B)
            frac2 = v2/t2 if t2>0 else 0.0
            print(f"  confirm: {v2}/{t2} frac={frac2:.2f}")
            if frac2 >= AUTO_ACCEPT_THRESHOLD:
                print("  accept after confirm:", bit)
                prefix_int = cand; prefix_len = cand_len; decided=True; break
        if not decided:
            raise RuntimeError(f"Ambiguous at bit {prefix_len+1}, adjust parameters.")
        if prefix_len % 8 == 0:
            print(f"[progress] accepted {prefix_len}/{B} bits")
    top_bits = bin(prefix_int)[2:].zfill(prefix_len)
    if len(top_bits) < 258:
        raise RuntimeError("Not enough bits recovered")
    slice_bits = top_bits[2:258:2]
    if len(slice_bits) != want_bits:
        raise RuntimeError("Unexpected slice length")
    return slice_bits

def bits_to_key(bitstr):
    return int(bitstr,2).to_bytes(16,'big')

def decrypt_and_print(cipher_bytes, key):
    aes = AES.new(key, AES.MODE_ECB)
    pt = aes.decrypt(cipher_bytes)
    try:
        pad = pt[-1]
        if 1 <= pad <= 16 and pt.endswith(bytes([pad])*pad):
            pt = pt[:-pad]
    except:
        pass
    try:
        print("[FLAG]", pt.decode())
    except:
        print("[FLAG raw]", pt)

def main():
    print("[*] connecting to oracle...")
    oracle = RSAOracle(HOST, PORT, timeout=TIMEOUT)
    print("[*] cipher hex:", oracle.cipher_hex)
    print("[*] recovering modulus n via gcd trick...")
    n = recover_modulus_n(oracle, e=1337, trials=18)
    print("[+] recovered n bitlen:", n.bit_length())
    print("[*] auto bit recovery (this may take several minutes)...")
    slice_bits = auto_recover(oracle, n, B=TOP_BITS_TO_RECOVER, want_bits=128)
    print("[+] recovered slice:", slice_bits)
    key = bits_to_key(slice_bits)
    print("[*] AES key hex:", key.hex())
    decrypt_and_print(oracle.cipher, key)
    oracle.close()

if __name__ == "__main__":
    main()
