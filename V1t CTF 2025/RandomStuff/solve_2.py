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
decrypted_string = solve_part_2_decryption()

print(f"Chuỗi hex cần giải mã: { '6768107b1a357132741539783d6a661b5f3b' }")
print(f"Kết quả giải mã (Part 2 của flag): {decrypted_string}")