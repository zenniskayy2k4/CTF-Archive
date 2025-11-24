#!/usr/bin/env python3
from pwn import remote
import json
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

HOST = "leaky-rsa.chal.imaginaryctf.org"
PORT = 1337

def recv_json(r):
    """Nhận 1 object JSON từ server (bỏ qua dòng text khác)."""
    while True:
        line = r.recvline().decode().strip()
        if line.startswith("{"):
            return json.loads(line)

def main():
    r = remote(HOST, PORT)

    # Bỏ qua banner và lấy header JSON
    header = recv_json(r)
    n = int(header["n"])
    key_c = int(header["c"])
    iv = bytes.fromhex(header["iv"])
    ct = bytes.fromhex(header["ct"])

    # 1024 vòng oracle
    for _ in range(1024):
        idx_line = recv_json(r)                   # {"idx": ...}
        r.sendline(json.dumps({"c": 0}).encode()) # gửi đại
        b_line = recv_json(r)                     # {"b": ...}

    # Dòng cuối không phải JSON mà là số key_m
    key_m_line = r.recvline().decode().strip()
    key_m = int(key_m_line)

    # Tạo AES key và giải mã
    key = sha256(str(key_m).encode()).digest()[:16]
    flag_padded = AES.new(key, AES.MODE_CBC, iv=iv).decrypt(ct)
    flag = unpad(flag_padded, 16).decode()

    print(flag)

if __name__ == "__main__":
    main()
