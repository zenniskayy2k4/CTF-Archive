import os

# --- BƯỚC 1: Đọc file mã hóa ---

try:
    with open("flag.enc", "rb") as f:
        enc_data = f.read()
except FileNotFoundError:
    print("[-] LỖI: Không tìm thấy file flag.enc.")
    exit(1)

print(f"[+] Đã đọc {len(enc_data)} bytes từ file flag.enc.")

# --- BƯỚC 2: Khôi phục rand_byte_1 bằng Known-Plaintext Attack ---

PNG_SIGNATURE_FIRST_BYTE = 0x89

# Khôi phục các thành phần cho byte đầu tiên (i=0)
# Trường hợp i%4 == 0: enc_data = [(rand_byte_2 + 0x72), b_byte, ...]
enc_byte1_for_i0 = enc_data[0]
b_byte_for_i0 = enc_data[1]

# Khôi phục rand_byte_2 đã được dùng cho i=0
rand_byte_2_for_i0 = (enc_byte1_for_i0 - 0x72) & 0xFF

# Bây giờ giải phương trình để tìm rand_byte_1
# p[0] = (rand_byte_1 + 0) ^ b_byte_0 ^ rand_byte_2_0
# rand_byte_1 = p[0] ^ b_byte_0 ^ rand_byte_2_0
rand_byte_1 = PNG_SIGNATURE_FIRST_BYTE ^ b_byte_for_i0 ^ rand_byte_2_for_i0

print(f"[+] Đã khôi phục được rand_byte_1: {rand_byte_1} (0x{rand_byte_1:02x})")

# --- BƯỚC 3: Giải mã toàn bộ file ---

dec_data = bytearray()
enc_ptr = 0
i = 0

print("[*] Bắt đầu giải mã toàn bộ file...")

while enc_ptr < len(enc_data):
    xor_key_part1 = (rand_byte_1 + i) & 0xFF
    b_byte = 0
    recovered_rand_byte_2 = 0

    if (i % 4) == 0:
        if enc_ptr + 2 > len(enc_data): break
        byte1 = enc_data[enc_ptr]
        b_byte = enc_data[enc_ptr + 1]
        recovered_rand_byte_2 = (byte1 - 0x72) & 0xFF
        enc_ptr += 2
        
    elif (i % 4) == 1:
        if enc_ptr + 2 > len(enc_data): break
        byte1 = enc_data[enc_ptr]
        recovered_rand_byte_2 = enc_data[enc_ptr + 1]
        b_byte = (byte1 - 0xd8) & 0xFF
        enc_ptr += 2
        
    elif (i % 4) == 2:
        if enc_ptr + 3 > len(enc_data): break
        b_byte = enc_data[enc_ptr]
        recovered_rand_byte_2 = enc_data[enc_ptr + 1]
        enc_ptr += 3
        
    else: # i % 4 == 3
        if enc_ptr + 3 > len(enc_data): break
        recovered_rand_byte_2 = enc_data[enc_ptr]
        b_byte = enc_data[enc_ptr + 1]
        enc_ptr += 3

    p_byte = xor_key_part1 ^ b_byte ^ recovered_rand_byte_2
    dec_data.append(p_byte)
    i += 1

# --- BƯỚC 4: Ghi kết quả và xác minh ---

# Kiểm tra xem header đã giải mã có đúng không
if dec_data.startswith(b'\x89PNG\r\n\x1a\n'):
    print("[+] Xác minh thành công! Header của file PNG đã giải mã là chính xác.")
else:
    print("[!] CẢNH BÁO: Header của file PNG sau khi giải mã không đúng. Logic vẫn có thể sai.")
    print(f"    Header nhận được: {dec_data[:8]}")

with open("flag_dec.png", "wb") as f:
    f.write(dec_data)
    
print(f"[+] Hoàn thành! Đã giải mã {len(dec_data)} bytes.")
print("[+] Kết quả đã được lưu vào file 'flag_dec.png'. Mở file này để xem flag.")