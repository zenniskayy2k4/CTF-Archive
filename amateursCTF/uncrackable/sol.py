import string

# Lớp stream và hàm xor giữ nguyên
class stream():
    def __init__(self, state):
        self.state = state
    
    def next(self):
        out = self.state[0]
        self.state = self.state[1:] + bytes([(out + 1) % 256])
        return out
    
    def get_bytes(self, num):
        return bytes(self.next() for _ in range(num))

def xor(a, b):
    return bytes(i^j for i,j in zip(a,b))

# --- PHẦN 1: KHÔI PHỤC TRẠNG THÁI BAN ĐẦU (giống như trước) ---

try:
    with open("out.txt", "r") as f:
        ciphertext = bytes.fromhex(f.read())
except FileNotFoundError:
    print("Lỗi: Không tìm thấy file out.txt.")
    exit()

L = len(ciphertext)
FLAG_LEN = 47
initial_state = bytearray(FLAG_LEN)

print("[-] Phần 1: Khôi phục trạng thái ban đầu của keystream...")
# (Sử dụng trạng thái đã tìm thấy từ lần chạy trước để tiết kiệm thời gian)
# Nếu bạn muốn chạy lại quá trình khôi phục, hãy bỏ comment phần code bên dưới
# for i in range(FLAG_LEN):
#     best_guess = -1
#     max_score = -1
#     for g in range(256):
#         score = 0
#         for j in range(i, L - FLAG_LEN, FLAG_LEN): # Chỉ quét phần dữ liệu ngẫu nhiên
#             offset = (j - i) // FLAG_LEN
#             p_byte_val = ciphertext[j] ^ ((g + offset) % 256)
#             if ord('a') <= p_byte_val <= ord('z') or ord('A') <= p_byte_val <= ord('Z') or ord('0') <= p_byte_val <= ord('9'):
#                 score += 1
#         if score > max_score:
#             max_score = score
#             best_guess = g
#     initial_state[i] = best_guess
# initial_state = bytes(initial_state)

# Sử dụng trực tiếp kết quả từ lần chạy trước của bạn
initial_state = bytes.fromhex("6502a13c227310e4e1aa02364c21e712846454772f6991b1aa526141ea854554d5f96adfffed0156805c4a55d11ab2")

print(f"[+] Sử dụng trạng thái ban đầu đã khôi phục: {initial_state.hex()}")

# --- PHẦN 2: TÌM KIẾM OFFSET VÀ GIẢI MÃ FLAG ---

print("\n[-] Phần 2: Tìm kiếm offset chính xác của flag...")
ciphertext_flag = ciphertext[-FLAG_LEN:]

# Tìm kiếm trong một khoảng hợp lý xung quanh 19500 (dựa trên xác suất)
search_range = range(1, 20000) 

for offset in search_range:
    # 2a: Tạo lại rng với trạng thái ban đầu
    rng_recreated = stream(initial_state)
    
    # 2b: "Tua nhanh" bộ tạo
    rng_recreated.get_bytes(offset)
    
    # 2c: Lấy keystream ứng cử viên cho flag
    keystream_candidate = rng_recreated.get_bytes(FLAG_LEN)
    
    # 2d: Giải mã
    flag_candidate = xor(ciphertext_flag, keystream_candidate)
    
    # 2e: Kiểm tra
    if flag_candidate.startswith(b'amateursCTF{') and flag_candidate.endswith(b'}'):
        print(f"\n[+] TÌM THẤY FLAG tại offset = {offset}!")
        print(flag_candidate.decode())
        break
else: # Vòng lặp kết thúc mà không break
    print("\n[!] Không tìm thấy flag trong khoảng tìm kiếm. Thử mở rộng search_range.")