#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os, socket, sys, random, struct, time
from z3 import BitVec, BitVecVal, Solver, Concat, Extract, LShR, If, ZeroExt, sat

HOST = sys.argv[1] if len(sys.argv) > 1 else "52.59.124.14"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 5031
# số mẫu; 8–16 là đủ, tăng nếu máy khoẻ để solver “khóa” nghiệm nhanh hơn
NUM_SAMPLES = int(sys.argv[3]) if len(sys.argv) > 3 else 12
BATCH = 64  # service yêu cầu 64 block/lần (768 hex)

# ====== Bảng theo des.c ======  (P-perm 24 bit, S-box 8 bảng 4->3)
P = [8, 18, 3, 2, 15, 24, 10, 14, 20, 7, 5, 13, 1, 6, 21, 9, 4, 11, 23, 22, 12, 19, 16, 17]
SBOX = [
    [5,3,0,2,7,1,4,6, 1,6,4,7,5,0,3,2],
    [4,1,0,5,3,7,6,2, 1,4,0,5,2,6,3,7],
    [3,4,2,0,7,6,1,5, 3,7,6,0,4,2,1,5],
    [5,6,4,2,7,0,3,1, 6,5,7,2,1,3,4,0],
    [5,6,7,3,1,0,4,2, 3,6,2,1,7,4,0,5],
    [0,3,1,4,6,5,2,7, 0,3,5,4,7,6,1,2],
    [6,0,4,2,3,5,1,7, 0,6,7,3,2,1,4,5],
    [0,5,6,2,3,7,4,1, 2,4,0,7,3,1,5,6],
]

def recvline(s):
    buf = b""
    while not buf.endswith(b"\n"):
        chunk = s.recv(4096)
        if not chunk:
            break
        buf += chunk
    return buf

def query_encrypt(blocks48):
    """Gửi đúng 64 block (mỗi block 48-bit int), nhận về 64 block ciphertext (12 hex/block)."""
    assert len(blocks48) == 64
    with socket.create_connection((HOST, PORT), timeout=10) as s:
        banner = recvline(s)  # "Give your message in hexadecimal.\n"
        line = "".join(f"{b:012x}" for b in blocks48) + "\n"
        s.sendall(line.encode())
        out = recvline(s).strip().decode()
    C = [int(out[i*12:(i+1)*12], 16) for i in range(64)]
    return C

def collect_samples(nwant=12):
    """Thu thập >= nwant cặp (P,C)."""
    samples = []
    while len(samples) < nwant:
        Pblocks = [random.getrandbits(48) for _ in range(BATCH)]
        Cblocks = query_encrypt(Pblocks)
        samples.extend(list(zip(Pblocks, Cblocks)))
    return samples[:nwant]

# ====== Cài đặt round F, permutation và mã hoá dưới dạng Z3 (bit-vector) ======

def z3_expand_24_to_32(R24):
    # R24 là BV-24, ta build E là BV-32 đúng như C: 
    # for j in 0..6: E |= ((R >> (20-3j)) & 0xF) << (28-4j)
    # rồi E |= ((R & 7) << 1) | (R >> 23)
    R24 = Extract(23, 0, R24)  # đảm bảo width 24
    expanded = BitVecVal(0, 32)
    for j in range(7):
        s = 20 - 3*j
        # nibble là các bit [s+3 .. s] của R (vì (R>>s)&0xF)
        hi = s + 3  # = 23,20,17,...,5
        lo = s      # = 20,17,14,...,2
        nib = Extract(hi, lo, R24)     # 4-bit
        expanded = expanded | (ZeroExt(28, nib) << (28 - 4*j))
    # phần "biên": ((R & 7) << 1) | (R >> 23)
    term1 = ZeroExt(8, (R24 & BitVecVal(7, 24)) << 1)   # -> 32-bit
    term2 = ZeroExt(8, LShR(R24, 23))                   # -> 32-bit
    expanded = expanded | term1 | term2
    return expanded

def z3_sbox_out(nibble4, box_index):
    """SBOX[box_index][nibble4] trả về 3-bit BitVec"""
    out = BitVecVal(0, 3)
    # Tra bằng chuỗi If (16 lựa chọn)
    for v in range(16):
        out = If(nibble4 == BitVecVal(v, 4), BitVecVal(SBOX[box_index][v], 3), out)
    return out

def z3_F(R24, k32):
    E = z3_expand_24_to_32(R24) ^ k32
    # Lấy 8 nibble 4-bit từ E theo đúng C: t = (E >> (4*j)) & 0xF  (j = 0..7)
    parts = []
    for j in range(8):
        nib = Extract(4*j + 3, 4*j, E)   # 4-bit
        s3  = z3_sbox_out(nib, j)        # 3-bit
        parts.append(s3)
    # Trong C: s_output <<= 3; s_output |= S[j][t]; (j từ 0..7)
    # => thứ tự là S0|S1|...|S7 (S0 ở cao nhất). Concat theo đúng thứ tự đó:
    s_concat = Concat(parts[0], parts[1], parts[2], parts[3], parts[4], parts[5], parts[6], parts[7])  # 24-bit

    # Áp P: p_out <<=1; p_out |= (s_output >> (24 - P[j])) & 1;
    p_out = BitVecVal(0, 24)
    for j in range(24):
        bitpos = 24 - P[j]   # 0..23
        bit = Extract(bitpos, bitpos, s_concat)  # 1-bit
        p_out = (p_out << 1) | ZeroExt(23, bit)  # nâng 1-bit lên 24-bit trước khi OR
    return p_out

def z3_encrypt_block(M48, k0, k1, rounds=32):
    """Mô phỏng đúng vòng Feistel (L,R là 24-bit) theo des.c (round 0 dùng k0, 1 dùng k1, ...)"""
    L = Extract(47, 24, M48)
    R = Extract(23, 0,  M48)
    for i in range(rounds):
        sub = If(BitVecVal(i & 1, 32) == BitVecVal(0, 32), k0, k1)
        fout = z3_F(R, sub)
        L, R = R, L ^ fout
    return Concat(L, R)  # 48-bit

# Bản Python “thường” để verify sau khi đã tìm được key
def py_expand_24_to_32(R):
    expanded = 0
    for j in range(7):
        expanded |= ((R >> (20 - 3*j)) & 0xF) << (28 - 4*j)
    expanded |= ((R & 7) << 1) | (R >> 23)
    return expanded

def py_F(R, k):
    E = py_expand_24_to_32(R) ^ k
    s_out = 0
    for j in range(8):
        t = (E >> (4*j)) & 0xF
        s_out = (s_out << 3) | SBOX[j][t]
    # P
    p_out = 0
    for j in range(24):
        p_out = (p_out << 1) | ((s_out >> (24 - P[j])) & 1)
    return p_out

def py_encrypt(M, k0, k1, rounds=32):
    L = (M >> 24) & 0xFFFFFF
    R = M & 0xFFFFFF
    for i in range(rounds):
        sub = k0 if (i % 2 == 0) else k1
        L, R = R, (L ^ py_F(R, sub)) & 0xFFFFFF
    return ((L & 0xFFFFFF) << 24) | (R & 0xFFFFFF)

def main():
    print(f"[+] Kết nối {HOST}:{PORT} để lấy {NUM_SAMPLES} mẫu…")
    samples = collect_samples(NUM_SAMPLES)
    print(f"[+] Đã thu {len(samples)} cặp (P,C). Dựng mô hình Z3…")

    # Biến key 32-bit mỗi cái
    k0 = BitVec('k0', 32)
    k1 = BitVec('k1', 32)

    s = Solver()
    # Ràng buộc: với mỗi (P,C) ta có des(P, k0||k1) == C
    for (P48, C48) in samples:
        P_bv = BitVecVal(P48, 48)
        C_bv = BitVecVal(C48, 48)
        E_bv = z3_encrypt_block(P_bv, k0, k1, rounds=32)
        s.add(E_bv == C_bv)

    t0 = time.time()
    print("[*] Đang solve… (mất vài phút tuỳ máy)")
    ok = s.check()
    t1 = time.time()
    if ok != sat:
        print("[-] UNSAT/UNKNOWN — tăng NUM_SAMPLES và chạy lại.")
        sys.exit(1)
    m = s.model()
    k0_val = m[k0].as_long() & 0xffffffff
    k1_val = m[k1].as_long() & 0xffffffff
    fullkey = ((k0_val << 32) | k1_val) & 0xffffffffffffffff
    print(f"[+] Solve xong sau {t1-t0:.1f}s")
    print(f"[+] k0 = 0x{k0_val:08x}, k1 = 0x{k1_val:08x}")
    print(f"FLAG: ENO{{{fullkey:016x}}}")

    # Kiểm tra nhanh bằng mã hoá cục bộ các mẫu đã thu
    ok_all = True
    for (P48, C48) in samples[:min(6, len(samples))]:
        if py_encrypt(P48, k0_val, k1_val, 32) != C48:
            ok_all = False
            break
    print("[*] Verify local:", "OK" if ok_all else "FAIL (tăng mẫu và solve lại)")

if __name__ == "__main__":
    main()
