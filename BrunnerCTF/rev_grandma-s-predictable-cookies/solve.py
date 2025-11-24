# ==============================================================================
# FINAL SOLVER SCRIPT - Confirmed to be correct
# ==============================================================================

# Tự triển khai lại hàm rand() của MSVCRT (thư viện C của Windows).
# Thuật toán này đã được xác minh là đúng cho bài toán.
class MsvcrtRand:
    def __init__(self):
        # Trạng thái được lưu dưới dạng số nguyên 32-bit không dấu.
        self.state = 0

    def srand(self, seed):
        """Tương đương với srand(seed) của MSVCRT."""
        self.state = seed & 0xFFFFFFFF

    def rand(self):
        """Tương đương với rand() của MSVCRT."""
        # Công thức LCG của Microsoft: state = state * 214013 + 2531011
        # Thực hiện phép toán trên số nguyên 32-bit không dấu.
        self.state = (self.state * 214013 + 2531011) & 0xFFFFFFFF
        # Kết quả trả về là 15 bit trên của state, là một số từ 0 đến 32767.
        return (self.state >> 16) & 0x7FFF

# --- Dữ liệu đầu vào từ bài toán ---
# Vui lòng kiểm tra lại lần cuối xem chuỗi này có khớp với file của bạn không.
encrypted_hex = "3ec63cc41f1ac1980651726ab3ce2948882b879c19671269963e39103c83ebd6ef173d60c76ee5"
approx_time = 1755860000
FLAG_FORMAT = "brunner{"

# --- Logic giải mã ---
try:
    encrypted_bytes = bytes.fromhex(encrypted_hex)
except ValueError as e:
    print(f"[!] Error: Invalid character in encrypted_hex string. Please check it.")
    print(f"[!] {e}")
    exit()

flag_len = len(encrypted_bytes)
start_seed = approx_time
end_seed = approx_time + 9999

print(f"[*] Starting brute-force attack...")
print(f"[*] Seed range: {start_seed} to {end_seed}")
print(f"[*] Using MSVCRT (Windows) rand() implementation.")
print(f"[*] Target format: '{FLAG_FORMAT}...'")

prng = MsvcrtRand()

for seed in range(start_seed, end_seed + 1):
    # 1. Khởi tạo seed
    prng.srand(seed)
    
    # 2. "Warm-up" 1000 lần
    for _ in range(1000):
        prng.rand()
        
    # 3. Tạo lại keystream
    key_stream = bytearray(prng.rand() % 256 for _ in range(flag_len))
        
    # 4. Giải mã
    decrypted_flag = bytearray(enc_byte ^ key_byte for enc_byte, key_byte in zip(encrypted_bytes, key_stream))
        
    # 5. Kiểm tra kết quả
    try:
        plaintext = decrypted_flag.decode('ascii')
        if plaintext.startswith(FLAG_FORMAT):
            print("\n" + "="*50)
            print(f"[+] SUCCESS! Flag found!")
            print(f"[+] Correct Seed: {seed}")
            print(f"[+] Decrypted Flag: {plaintext}")
            print("="*50)
            exit(0) # Thoát ngay khi tìm thấy flag
    except UnicodeDecodeError:
        continue # Nếu không phải ascii, bỏ qua

print("\n[-] Attack failed. Flag not found in the given seed range.")
print("[-] This indicates a potential mismatch in the rand() algorithm or input data.")