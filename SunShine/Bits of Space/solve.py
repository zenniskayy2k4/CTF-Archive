from pwn import *
import struct

# Thông tin kết nối
HOST = 'sunshinectf.games'
PORT = 25401

# Đọc file voyager.bin
with open("voyager.bin", "rb") as f:
    original_packet = f.read()

# Tách IV và Ciphertext gốc
iv_original = original_packet[:16]
ciphertext_original = original_packet[16:]

# Device ID gốc (xác định bằng cách gửi file gốc) và ID mục tiêu
id_original = 0x13371337
id_target   = 0xdeadbabe

print(f"[*] ID Gốc     : {hex(id_original)}")
print(f"[*] ID Mục tiêu : {hex(id_target)}")

# Đóng gói các ID thành chuỗi byte (4 bytes, little-endian)
id_original_bytes = struct.pack('<I', id_original)
id_target_bytes   = struct.pack('<I', id_target)

# Tính toán sự khác biệt cần tạo ra trong plaintext
# Chỉ cần XOR 4 byte đầu, 12 byte còn lại không đổi (XOR với 0)
plaintext_xor_diff = xor(id_original_bytes, id_target_bytes) + (b'\x00' * 12)

# Tạo IV mới bằng cách áp dụng phép XOR
# IV_new = IV_original XOR Plaintext_original XOR Plaintext_target
iv_crafted = xor(iv_original, plaintext_xor_diff)
print(f"[*] IV Gốc     : {iv_original.hex()}")
print(f"[*] IV Tấn công : {iv_crafted.hex()}")

# Tạo gói tin tấn công
malicious_packet = iv_crafted + ciphertext_original

# Kết nối, gửi gói tin và nhận flag
r = remote(HOST, PORT)
r.recvuntil(b"Send your subscription packet:\n")
r.send(malicious_packet)

# Nhận và in tất cả phản hồi từ server
response = r.recvall(timeout=2)
print("\n--- PHẢN HỒI TỪ SERVER ---")
print(response.decode())