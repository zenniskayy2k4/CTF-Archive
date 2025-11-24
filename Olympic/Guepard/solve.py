import struct

# --- Cấu hình ---
GUEPARD_BINARY_PATH = "Guepard"
ENCRYPTED_FILE_PATH = "flag.enc"
DECRYPTED_FILE_PATH = "decrypted_flag.txt"

# --- Tái triển khai thuật toán ChaCha20 Variant (ĐÃ SỬA LỖI CUỐI CÙNG) ---

def rotl32(v, c):
    """Quay trái 32-bit."""
    return ((v << c) & 0xFFFFFFFF) | (v >> (32 - c))

def quarter_round(state, a, b, c, d):
    """Thực hiện một ChaCha20 Quarter Round."""
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] = rotl32(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] = rotl32(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] = rotl32(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] = rotl32(state[b] ^ state[c], 7)

def chacha_block_variant(initial_state):
    """
    Tạo ra một khối keystream 64-byte.
    Sửa lỗi: Đảo ngược thứ tự byte của mỗi word trong keystream cuối cùng.
    """
    working_state = list(initial_state)
    
    for _ in range(10):
        # Vòng cột và vòng chéo của ChaCha20
        quarter_round(working_state, 0, 4, 8, 12)
        quarter_round(working_state, 1, 5, 9, 13)
        quarter_round(working_state, 2, 6, 10, 14)
        quarter_round(working_state, 3, 7, 11, 15)
        quarter_round(working_state, 0, 5, 10, 15)
        quarter_round(working_state, 1, 6, 11, 12)
        quarter_round(working_state, 2, 7, 8, 13)
        quarter_round(working_state, 3, 4, 9, 14)
        
    # Keystream là working_state cộng với initial_state (đây là chuẩn ChaCha20)
    keystream_words = [(working_state[i] + initial_state[i]) & 0xFFFFFFFF for i in range(16)]
    
    # *** CHI TIẾT QUYẾT ĐỊNH ***
    # Chương trình đảo ngược thứ tự byte của mỗi word trước khi sử dụng.
    # Chúng ta pack nó dưới dạng little-endian ('<') rồi unpack dưới dạng big-endian ('>')
    # để mô phỏng phép bswap trên từng word.
    # Hoặc đơn giản hơn, pack nó dưới dạng big-endian.
    return struct.pack('>16L', *keystream_words)

def derive_key(key_data):
    """Tạo khóa 32-byte từ dữ liệu."""
    derived_key = bytearray(32)
    for i, byte in enumerate(key_data):
        derived_key[i % 32] ^= byte
    return bytes(derived_key)

def solve():
    # Các bước 1-4 không đổi
    print(f"[*] Đang đọc khóa từ file binary: {GUEPARD_BINARY_PATH}")
    try:
        with open(GUEPARD_BINARY_PATH, "rb") as f:
            binary_data = f.read()
    except FileNotFoundError:
        print(f"Lỗi: Không tìm thấy file binary '{GUEPARD_BINARY_PATH}'")
        return
    key = derive_key(binary_data)
    print(f"[*] Khóa 32-byte đã được tạo: {key.hex()}")

    print(f"[*] Đang đọc file đã mã hóa: {ENCRYPTED_FILE_PATH}")
    try:
        with open(ENCRYPTED_FILE_PATH, "rb") as f:
            encrypted_data = f.read()
    except FileNotFoundError:
        print(f"Lỗi: Không tìm thấy file đã mã hóa '{ENCRYPTED_FILE_PATH}'")
        return
    nonce = encrypted_data[:8]
    ciphertext = encrypted_data[8:-8]
    print(f"[*] Nonce được trích xuất: {nonce.hex()}")

    state = [0] * 16
    key_words = struct.unpack('<8L', key)
    nonce_words = struct.unpack('<2L', nonce)
    state[0], state[5], state[10], state[15] = 0xffffff83, 0xff8b6f7c, 0xffffffd0, 0xffc7566f
    state[1:5] = key_words[0:4]
    state[11:15] = key_words[4:8]
    state[6:8] = nonce_words[0:2]
    state[8:10] = [0, 0]
    print("[*] Trạng thái tùy chỉnh đã được khởi tạo.")

    # Bước 5: Giải mã với logic đã sửa
    print("[*] Đang giải mã dữ liệu...")
    plaintext = bytearray()
    
    for i in range(0, len(ciphertext), 64):
        chunk = ciphertext[i:i+64]
        keystream = chacha_block_variant(state)
        
        for j in range(len(chunk)):
            plaintext.append(chunk[j] ^ keystream[j])
            
        state[8] = (state[8] + 1) & 0xFFFFFFFF
        if state[8] == 0:
            state[9] = (state[9] + 1) & 0xFFFFFFFF

    # Bước 6: Lưu và hiển thị kết quả
    try:
        with open(DECRYPTED_FILE_PATH, "wb") as f:
            f.write(plaintext)
        print(f"[+] Giải mã thành công! Flag được lưu tại: {DECRYPTED_FILE_PATH}")
        print("\n--- Nội dung Flag ---")
        print(plaintext.decode('utf-8', errors='ignore'))
        print("---------------------\n")
    except Exception as e:
        print(f"Lỗi khi ghi file output: {e}")

# Chạy hàm giải
solve()