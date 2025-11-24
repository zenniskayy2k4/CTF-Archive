from pwn import *
from Crypto.Cipher import DES
from Crypto.Hash import MD5
import os
import re

# --- Cấu hình ---
context.log_level = 'info'
HOST = "chals.ctf.csaw.io"
PORT = 21000

SPACESHIP_NAME = b"a" * 8
ACCESS_CODE = b"b" * 8
PAYLOAD_AUTH = SPACESHIP_NAME + ACCESS_CODE
FULL_AUTH_STRING = SPACESHIP_NAME + ACCESS_CODE
KEY1 = MD5.new(FULL_AUTH_STRING).digest()[:8]
cipher1 = DES.new(KEY1, DES.MODE_ECB)

def build_packet(type1, type2, seq, length, rand_byte, payload):
    header = p8(type1) + p8(type2) + p8(1) + p16(seq, endian='big') + p16(length, endian='big') + p8(rand_byte)
    header += b'\x00' * 16
    return header + payload

def get_authenticated_connection():
    log.info("Starting Stage 1: Brute-forcing auth byte...")
    for byte_to_try in range(256):
        try:
            p = remote(HOST, PORT, timeout=2)
            p.sendlineafter(b"name: ", SPACESHIP_NAME)
            p.sendlineafter(b"code: ", ACCESS_CODE)
            p.recvuntil(b'Authenticating your entry...\n')
            log.info(f"Trying auth byte: {hex(byte_to_try)}")
            auth_packet = build_packet(1, 5, 0, len(PAYLOAD_AUTH), byte_to_try, PAYLOAD_AUTH)
            p.send(auth_packet)
            response = p.recvuntil(b"authenticated!", timeout=1)
            if b"authenticated" in response:
                log.success(f"Authentication successful with byte: {hex(byte_to_try)}")
                return p
        except (EOFError, PwnlibException):
            p.close()
            continue
    return None

def solve():
    conn = get_authenticated_connection()
    if not conn:
        log.error("Stage 1 Failed."); return

    log.info("Starting Stage 2: Recovering signature...")
    # Gói tin rò rỉ được gửi đi ngay sau chuỗi text này.
    conn.recvuntil(b"leaked information!\n")
    leaked_data_packet = conn.recv(0x18 + 8)
    # Lấy seq_num cho bước tiếp theo từ chính gói tin rò rỉ này
    seq_num_for_next_step = u16(leaked_data_packet[3:5], endian='big')
    log.info(f"Captured sequence number for Stage 3: {seq_num_for_next_step}")
    
    inverted_noted_signature = cipher1.decrypt(leaked_data_packet[0x18:])
    signature = bytes([b ^ 0xFF for b in inverted_noted_signature])[::-1]
    log.success(f"Signature recovered (KEY2): {signature.hex()}")
    KEY2 = signature

    log.info("Starting Stage 3: Signature Validation...")
    # Chỉ cần đọc chuỗi text prompt
    conn.recvuntil(b"Validating signature...\n")
    
    for byte_to_try in range(256):
        # Sử dụng seq_num đã lấy được từ Stage 2
        xor_payload = bytes([b ^ byte_to_try for b in signature])
        sig_packet = build_packet(1, ord('L'), seq_num_for_next_step, len(xor_payload), byte_to_try, xor_payload)
        conn.send(sig_packet)
        response = conn.recvline()
        if b"valid" in response:
            log.success(f"Signature validation successful with byte: {hex(byte_to_try)}")
            break
    else:
        log.error("Stage 3 Failed."); conn.close(); return

    log.info("Starting Stage 4: Capturing the Leaked Flag...")
    conn.recvuntil(b"Sending coordinate...\n")
    
    leaked_data = conn.recvall()
    log.info(f"Captured {len(leaked_data)} bytes of raw leaked data.")

    encrypted_leaked_payload = leaked_data[24:]
    
    if not encrypted_leaked_payload:
        log.error("No leaked payload data was captured."); conn.close(); return
        
    if len(encrypted_leaked_payload) % 8 != 0:
        padding_needed = 8 - (len(encrypted_leaked_payload) % 8)
        encrypted_leaked_payload += b'\x00' * padding_needed

    log.info("Decrypting the leaked data with KEY2...")
    cipher2 = DES.new(KEY2, DES.MODE_ECB)
    decrypted_data = cipher2.decrypt(encrypted_leaked_payload)
    
    log.info("--- DECRYPTED DATA ---")
    log.info(f"ASCII (repr): {repr(decrypted_data)}")
    
    match = re.search(b'csawctf\\{.*?}', decrypted_data)
    if match:
        flag = match.group(0)
        log.success(f"FLAG FOUND: {flag.decode('utf-8', 'ignore')}")
    else:
        log.warning("Could not find a complete flag pattern. The flag is likely the beginning of the decrypted data.")

    conn.close()

if __name__ == "__main__":
    solve()