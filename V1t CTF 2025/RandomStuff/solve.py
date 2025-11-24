from Crypto.Util.number import *
from hashlib import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import *

# Các giá trị đã biết từ output của bài toán
enc = b'\xe6\x97\x9f\xb9\xc9>\xde\x1e\x85\xbb\xebQ"Ii\xda\'\x1f\xae\x19\x05M\x01\xe1kzS\x8fi\xf4\x8cz'
a = 958181900694223
c = 1044984108221161
m = 675709840048419795804542182249
lcg_next_output = 176787694147066159797379

# --- Chuẩn bị các giá trị cần thiết cho việc tính toán ---
print("Đang chuẩn bị các giá trị tính toán...")

# Nghịch đảo modular của a theo m
a_inv = pow(a, -1, m)

# "Số mũ bí mật" d để đảo ngược phép lũy thừa e=65537
e = 65537
# Vì m là số nguyên tố, phi(m) = m - 1
d = pow(e, -1, m - 1)

print("Bắt đầu lặp qua 2^20 khả năng...")

# --- Lặp qua 2^20 khả năng của 20 bit đã mất ---
num_lost_bits = 20
num_possibilities = 1 << num_lost_bits # Tương đương 2**20

for x in range(num_possibilities):
    # Xây dựng lại trạng thái mới đầy đủ
    new_state_candidate = (lcg_next_output << num_lost_bits) + x
    
    # Giải phương trình để tìm Y = seed^e
    Y = ((new_state_candidate - c) * a_inv) % m
    
    # Tính seed_candidate bằng cách lấy căn bậc e
    seed_candidate = pow(Y, d, m)
    
    # --- Kiểm tra seed_candidate có đúng không ---
    key_candidate = sha256(long_to_bytes(seed_candidate)).digest()
    cipher = AES.new(key_candidate, AES.MODE_ECB)
    
    try:
        # Thử giải mã và bỏ padding
        decrypted_part_1 = unpad(cipher.decrypt(enc), 16)
        
        # Nếu không có lỗi, chúng ta đã tìm thấy!
        # print("\n--- TÌM THẤY! ---")
        # print(f"Seed chính xác là: {seed_candidate}")
        print(f"Part 1 của flag là: {decrypted_part_1.decode()}")
        break # Thoát khỏi vòng lặp

    except ValueError:
        # Lỗi padding, đây là seed sai, tiếp tục tìm kiếm
        continue

# In ra thông báo nếu không tìm thấy (để debug)
else:
    print("\nKhông tìm thấy seed nào phù hợp.")
    
def scramble(v_orig):
    """Hàm scramble gốc từ bài toán, dùng để tạo bảng tra cứu."""
    v = v_orig & 0xFF
    v ^= (v >> 4)
    v ^= (v >> 3)
    v ^= (v >> 2)
    v ^= (v >> 1)
    return v & 0xFF

# --- Tạo bảng tra cứu để đảo ngược hàm scramble một cách đáng tin cậy ---
# Bảng này sẽ map: scrambled_value -> original_value
unscramble_lookup_table = {scramble(i): i for i in range(256)}

def unscramble(scrambled_byte):
    """Sử dụng bảng tra cứu để đảo ngược một cách chính xác."""
    return unscramble_lookup_table[scrambled_byte]

def solve_part_2_decryption():
    """
    Giải mã chuỗi hex bằng cách đảo ngược chính xác thuật toán đã cho.
    """
    hex_input = "6768107b1a357132741539783d6a661b5f3b"
    scrambled_bytes = list(bytes.fromhex(hex_input))
    
    # Mảng để lưu kết quả giải mã
    original_bytes = bytearray()
    
    # --- Bước 1: Giải mã byte đầu tiên (i=0) ---
    # Không có XOR, chỉ có scramble.
    # P[0] = unscramble(S[0])
    unscrambled_first_byte = unscramble(scrambled_bytes[0])
    original_bytes.append(unscrambled_first_byte)
    
    # --- Bước 2: Giải mã các byte còn lại (i > 0) ---
    for i in range(1, len(scrambled_bytes)):
        # Lấy byte đã scramble của bước trước đó để đảo ngược phép XOR
        previous_scrambled_byte = scrambled_bytes[i-1]
        
        # Unscramble byte hiện tại để có được giá trị trung gian (X[i])
        xor_byte = unscramble(scrambled_bytes[i])
        
        # Đảo ngược XOR: P[i] = X[i] ^ S[i-1]
        plain_byte = xor_byte ^ previous_scrambled_byte
        original_bytes.append(plain_byte)
        
    # Trả về chuỗi đã giải mã
    return original_bytes.decode('utf-8')

# Chạy hàm giải mã và in kết quả
part_2_flag = solve_part_2_decryption()

print(f"Kết quả giải mã (Part 2 của flag): {part_2_flag}")


print("Full Flag:", decrypted_part_1.decode() + part_2_flag)