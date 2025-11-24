import os
import binascii

# --- Implementation của thuật toán RC4 ---
def rc4_decrypt(key, data):
    S = list(range(256))
    j = 0
    out = []

    # Giai đoạn KSA (Key-scheduling algorithm)
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]

    # Giai đoạn PRGA (Pseudo-random generation algorithm)
    i = j = 0
    for char in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(char ^ S[(S[i] + S[j]) % 256])

    return bytes(out)

# --- Hàm để XOR hai chuỗi bytes ---
def xor_bytes(b1, b2):
    return bytes([_a ^ _b for _a, _b in zip(b1, b2)])

# --- Hàm để trích xuất MD5 từ file ảnh ---
def get_md5_from_file(filepath):
    # Sử dụng lệnh `strings` và `grep` giống như chúng ta đã làm
    command = f"strings '{filepath}' | grep -E '^[0-9a-f]{{32}}$'"
    try:
        result = os.popen(command).read().strip()
        if len(result) == 32:
            print(f"  [+] Tìm thấy MD5: {result}")
            return result
    except Exception as e:
        print(f"  [-] Không tìm thấy MD5 trong file {filepath}: {e}")
    return None

# --- Cấu hình ---
BLOCKCHAIN_DIR = "./nft_blockchain"
OUTPUT_DIR = "./output"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# --- Bắt đầu ---

# MD5 genesis từ block_0, cũng là khóa ban đầu
genesis_md5_hex = "5d80299b6158525b512c93d7f9a2b896"
print(f"Bắt đầu với MD5 genesis: {genesis_md5_hex}")

# Khóa giải mã lũy tiến, ban đầu là MD5 của block_0
progressive_key_hex = genesis_md5_hex
progressive_key_bytes = binascii.unhexlify(progressive_key_hex)

# Các file cần giải mã theo thứ tự
encrypted_files = [
    "block_1_shark-bites-01_encrypted.jpg",
    "block_2_ceno-bites-01_encrypted.jpg",
    "block_3_xenomorph-mallows-01_encrypted.jpg",
    "block_4_krampuffs-01_encrypted.jpg",
    "block_5_fruity-krueger-01_encrypted.xcf"
]

for filename in encrypted_files:
    print(f"\n[+] Đang xử lý file: {filename}")
    print(f"  [i] Sử dụng khóa: {progressive_key_bytes.hex()}")

    encrypted_path = os.path.join(BLOCKCHAIN_DIR, filename)
    decrypted_path = os.path.join(OUTPUT_DIR, filename.replace("_encrypted", ""))

    # Đọc dữ liệu đã mã hóa
    with open(encrypted_path, 'rb') as f:
        encrypted_data = f.read()

    # Giải mã bằng RC4
    decrypted_data = rc4_decrypt(progressive_key_bytes, encrypted_data)

    # Lưu file đã giải mã
    with open(decrypted_path, 'wb') as f:
        f.write(decrypted_data)
    print(f"  [+] Đã giải mã và lưu vào: {decrypted_path}")

    # Trích xuất MD5 từ file vừa giải mã để dùng cho block tiếp theo
    # (Bỏ qua với file cuối cùng vì không còn block nào để giải mã)
    if not filename.endswith(".xcf"):
        next_md5_hex = get_md5_from_file(decrypted_path)
        if next_md5_hex:
            next_md5_bytes = binascii.unhexlify(next_md5_hex)
            # Cập nhật khóa: key_new = key_old XOR md5_new
            progressive_key_bytes = xor_bytes(progressive_key_bytes, next_md5_bytes)
        else:
            print("  [!] Không tìm thấy MD5, không thể tiếp tục!")
            break

print("\n[+] Hoàn thành!")