#!/usr/bin/env sage
# -*- coding: utf-8 -*-

from pwn import remote, context, log as pwnlog, PwnlibException
from sage.all import *
import json
import base64
import hashlib
import binascii
import time

# --- CÁC THAM SỐ TỪ SERVER ---
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# --- CẤU HÌNH ---
HOST = "0.cloud.chals.io"
PORT = 19521
NUM_SIGS_NEEDED = 40 # Giữ nguyên số lượng, cần thiết cho LLL
context.log_level = 'info'
context.timeout = 30 # Tăng thời gian chờ để ổn định hơn

# --- CÁC HÀM TIỆN ÍCH ---

def parse_ticket(ticket_b64):
    """Phân tích chuỗi base64 của vé để lấy ra các thông tin cần thiết."""
    try:
        decoded = base64.b64decode(ticket_b64)
        ticket_json = json.loads(decoded)
        payload = ticket_json['payload']
        ticket_id = int(payload['ticket_id'])
        
        payload_bytes = json.dumps({"ticket_id": ticket_id}, separators=(',', ':'), sort_keys=True).encode()
        z = Integer(int.from_bytes(hashlib.sha256(payload_bytes).digest(), 'big'))
        
        sig_hex = ticket_json['signature']
        r = Integer(int(sig_hex[:64], 16))
        s = Integer(int(sig_hex[64:], 16))
        
        return {'tid': ticket_id, 'r': r, 's': s, 'z': z, 'b64': ticket_b64}
    except Exception:
        return None

# =====================================================================
# SỬA LỖI QUAN TRỌNG TẠI ĐÂY
# =====================================================================
def get_first_ticket(r):
    """Yêu cầu vé đầu tiên từ server (phiên bản đã sửa lỗi)."""
    pwnlog.info("Đang yêu cầu vé đầu tiên...")
    r.sendlineafter(b"Choose an action:\n", b"1")
    # Đọc tối đa 5 dòng, thử giải mã Base64 từng dòng
    for _ in range(5):
        try:
            line = r.recvline().strip().decode()
            if not line: continue
            # Thử giải mã, nếu thành công, đó chính là vé
            base64.b64decode(line, validate=True)
            pwnlog.success("Nhận được vé đầu tiên!")
            return line
        except (binascii.Error, ValueError):
            # Bỏ qua nếu không phải Base64
            continue
    return None
# =====================================================================

def claim_and_get_new(r, old_ticket_b64):
    """Gửi vé cũ (nếu tid chẵn) để nhận vé mới."""
    r.sendlineafter(b"Choose an action:\n", b"2")
    r.sendlineafter(b"Enter your ticket: \n", old_ticket_b64.encode())
    for _ in range(5):
        line = r.recvline().strip().decode()
        prefix = "You won a brand new ticket: "
        if line.startswith(prefix):
            return line[len(prefix):]
    return None

# --- GIAI ĐOẠN 1: THU THẬP DỮ LIỆU ---

def collect_signatures(num_needed):
    attempt = 0
    while True:
        attempt += 1
        pwnlog.info(f"--- Bắt đầu lượt thu thập #{attempt} ---")
        signatures = []
        r = None
        try:
            r = remote(HOST, PORT)
            # Bỏ qua banner đầu game một cách đáng tin cậy
            r.recvuntil(b"guaranteed to win!")
            
            current_b64 = get_first_ticket(r)
            if not current_b64:
                pwnlog.warning("Không nhận được vé đầu tiên.")
                r.close()
                continue
            
            parsed = parse_ticket(current_b64)
            if not parsed:
                pwnlog.warning("Không phân tích được vé đầu tiên.")
                r.close()
                continue
            signatures.append(parsed)

            while len(signatures) < num_needed:
                last_ticket = signatures[-1]
                pwnlog.info(f"Đã có {len(signatures)}/{num_needed} chữ ký. Ticket ID cuối: ...{str(last_ticket['tid'])[-10:]} (là {'chẵn' if last_ticket['tid'] % 2 == 0 else 'lẻ'})")

                if last_ticket['tid'] % 2 == 0:
                    current_b64 = claim_and_get_new(r, last_ticket['b64'])
                    if not current_b64:
                        pwnlog.warning("Chuỗi bị đứt: không nhận được vé mới từ server.")
                        break
                    
                    parsed = parse_ticket(current_b64)
                    if not parsed:
                        pwnlog.warning("Không phân tích được vé mới.")
                        break
                    signatures.append(parsed)
                else:
                    pwnlog.warning("Chuỗi bị đứt: Ticket ID là số lẻ.")
                    break
            
            if len(signatures) >= num_needed:
                pwnlog.success(f"Thu thập thành công {len(signatures)} chữ ký sau {attempt} lượt!")
                r.close()
                return signatures

        except (PwnlibException, EOFError) as e:
            pwnlog.error(f"Lỗi kết nối: {e}. Đang thử lại...")
        finally:
            if r:
                r.close()
            time.sleep(1) # Chờ 1 giây trước khi thử lại để tránh flood server

# --- GIAI ĐOẠN 2: TẤN CÔNG LATTICE (giữ nguyên) ---

def solve_for_privkey(signatures):
    m = len(signatures)
    pwnlog.info(f"Bắt đầu tấn công lattice với {m} chữ ký.")
    B = Matrix(ZZ, m + 2, m + 2)

    for i in range(m):
        B[i, i] = N

    s_inv = [inverse_mod(sig['s'], N) for sig in signatures]

    for i in range(m):
        B[m, i] = (signatures[i]['r'] * s_inv[i]) % N
        B[m + 1, i] = (signatures[i]['z'] * s_inv[i]) % N

    B[m, m] = 1 
    B[m+1, m+1] = 1 

    pwnlog.info("Ma trận dàn đã được xây dựng. Bắt đầu giảm cơ sở bằng LLL...")
    B_lll = B.LLL()
    pwnlog.info("LLL hoàn tất. Đang tìm kiếm khóa bí mật...")
    
    for row in B_lll:
        # Giả định d nằm ở cột m và k0 nằm ở cột m+1. 
        # Cần kiểm tra dấu
        for sign in [1, -1]:
            d_candidate = (row[m] * sign) % N
            
            if d_candidate == 0: continue
            
            Q_candidate = d_candidate * G
            
            test_sig = signatures[0]
            r_test, s_test, z_test = test_sig['r'], test_sig['s'], test_sig['z']
            
            s_inv_test = inverse_mod(s_test, N)
            k_candidate = ((z_test + r_test * d_candidate) * s_inv_test) % N
            
            if (k_candidate * G).xy()[0] == r_test:
                pwnlog.success(f"ĐÃ TÌM THẤY KHÓA BÍ MẬT: {hex(d_candidate)}")
                return d_candidate
    return None

# --- GIAI ĐOẠN 3: GIẢ MẠO VÀ LẤY CỜ (giữ nguyên) ---

def forge_and_get_flag(d):
    # ... (Giữ nguyên phần này) ...
    pwnlog.info("Đang giả mạo vé chứa cờ...")
    target_msg = b"I'd like the flag please"
    target_tid = Integer(int.from_bytes(hashlib.sha256(target_msg).digest(), 'big'))
    payload = {"ticket_id": int(target_tid)} # JSON cần int thường
    payload_bytes = json.dumps(payload, separators=(',', ':'), sort_keys=True).encode()
    z_target = Integer(int.from_bytes(hashlib.sha256(payload_bytes).digest(), 'big'))
    k_forge = randint(1, N - 1)
    P = k_forge * G
    r_forge = Integer(P.xy()[0])
    k_inv_forge = inverse_mod(k_forge, N)
    s_forge = (k_inv_forge * (z_target + r_forge * d)) % N
    sig_hex = f"{int(r_forge):064x}{int(s_forge):064x}"
    forged_ticket = {"payload": payload, "signature": sig_hex}
    forged_b64 = base64.b64encode(json.dumps(forged_ticket, separators=(',', ':')).encode())
    pwnlog.info("Gửi vé giả mạo...")
    r = remote(HOST, PORT)
    r.sendlineafter(b"Choose an action:\n", b"2")
    r.sendlineafter(b"Enter your ticket: \n", forged_b64)
    pwnlog.success("PHẢN HỒI TỪ SERVER (CỜ):")
    print(r.recvall(timeout=5).decode(errors='ignore'))
    r.close()


if __name__ == "__main__":
    # --- THIẾT LẬP TOÁN HỌC ---
    F = GF(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F)
    E = EllipticCurve(F, [0, 7])
    G = E(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

    pwnlog.info("Bắt đầu quá trình giải quyết. Giai đoạn thu thập có thể mất rất nhiều thời gian, hãy kiên nhẫn.")
    collected_sigs = collect_signatures(NUM_SIGS_NEEDED)
    priv_key = solve_for_privkey(collected_sigs)
    if priv_key:
        forge_and_get_flag(priv_key)
    else:
        pwnlog.failure("Không thể tìm thấy khóa bí mật sau khi tấn công lattice.")