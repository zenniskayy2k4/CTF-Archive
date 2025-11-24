# S-DES (Simplified DES) Implementation and Brute-force Solver

# --- Bảng hoán vị và S-Boxes cố định của S-DES ---
P10 = (3, 5, 2, 7, 4, 10, 1, 9, 8, 6)
P8 = (6, 3, 7, 4, 8, 5, 10, 9)
P4 = (2, 4, 3, 1)

IP = (2, 6, 3, 1, 4, 8, 5, 7)
IP_INV = (4, 1, 3, 5, 7, 2, 8, 6)

EP = (4, 1, 2, 3, 2, 3, 4, 1)

S0 = [[1, 0, 3, 2], [3, 2, 1, 0], [0, 2, 1, 3], [3, 1, 3, 2]]
S1 = [[0, 1, 2, 3], [2, 0, 1, 3], [3, 0, 1, 0], [2, 1, 0, 3]]

# --- Các hàm phụ trợ ---
def permute(original, p_table):
    """Áp dụng một hoán vị cho chuỗi bit."""
    res = ""
    for i in p_table:
        res += original[i - 1]
    return res

def left_shift(bits):
    """Thực hiện dịch trái 1 bit trên mỗi nửa của chuỗi 10 bit."""
    left = bits[:5]
    right = bits[5:]
    return left[1:] + left[0] + right[1:] + right[0]

def xor(bits1, bits2):
    """Thực hiện phép XOR trên hai chuỗi bit."""
    return "".join(str(int(b1) ^ int(b2)) for b1, b2 in zip(bits1, bits2))

def s_box_lookup(bits, s_box):
    """Tra cứu giá trị trong S-Box."""
    row = int(bits[0] + bits[3], 2)
    col = int(bits[1] + bits[2], 2)
    return format(s_box[row][col], '02b')

# --- Các hàm chính ---
def generate_keys(key):
    """Tạo hai khóa con K1 và K2 từ khóa 10 bit."""
    p10_key = permute(key, P10)
    ls1_key = left_shift(p10_key)
    k1 = permute(ls1_key, P8)
    ls2_key = left_shift(left_shift(ls1_key))
    k2 = permute(ls2_key, P8)
    return k1, k2

def feistel_function(bits, key):
    """Hàm F (còn gọi là hàm Feistel) của S-DES."""
    left, right = bits[:4], bits[4:]
    expanded = permute(right, EP)
    xored = xor(expanded, key)
    s0_in, s1_in = xored[:4], xored[4:]
    s0_out = s_box_lookup(s0_in, S0)
    s1_out = s_box_lookup(s1_in, S1)
    p4_out = permute(s0_out + s1_out, P4)
    return xor(left, p4_out) + right

def sdes_decrypt(ciphertext_byte, key):
    """Giải mã một byte bằng S-DES."""
    k1, k2 = generate_keys(key)
    
    # Chuyển byte đầu vào (số nguyên) thành chuỗi nhị phân 8 bit
    bits = format(ciphertext_byte, '08b')
    
    # Áp dụng Initial Permutation (IP)
    ip_bits = permute(bits, IP)
    
    # Vòng 1 (sử dụng K2 trước vì đây là giải mã)
    round1_out = feistel_function(ip_bits, k2)
    
    # Swap hai nửa
    swapped = round1_out[4:] + round1_out[:4]
    
    # Vòng 2 (sử dụng K1)
    round2_out = feistel_function(swapped, k1)
    
    # Áp dụng hoán vị cuối cùng (IP^-1)
    plaintext_bits = permute(round2_out, IP_INV)
    
    # Chuyển chuỗi bit kết quả thành số nguyên
    return int(plaintext_bits, 2)

# --- Phần giải quyết thử thách ---
def solve_ctf():
    """Thực hiện tấn công vét cạn để tìm cờ."""
    hex_ciphertext = "D1D74C5F5FDDD7ECD8B29ED8019DD801B7F2AB0128573FB2019D1C018FF2E001E7B7F2870128F28701ABF20112E0D8AB015957E79EA2"
    ciphertext_bytes = bytes.fromhex(hex_ciphertext)
    
    print(f"Bắt đầu vét cạn {2**10} khóa...")
    
    for key_decimal in range(1024):
        # Chuyển khóa thập phân thành chuỗi nhị phân 10 bit
        key_binary = format(key_decimal, '010b')
        
        decrypted_bytes = bytearray()
        for byte in ciphertext_bytes:
            decrypted_byte = sdes_decrypt(byte, key_binary)
            decrypted_bytes.append(decrypted_byte)
            
        try:
            # Cố gắng giải mã kết quả dưới dạng text
            plaintext = decrypted_bytes.decode('utf-8')
            # Kiểm tra xem nó có phải là cờ không
            if "brunner" in plaintext:
                print("\n--- TÌM THẤY CỜ! ---")
                print(f"Khóa đúng (thập phân): {key_decimal}")
                print(f"Khóa đúng (nhị phân): {key_binary}")
                print(f"Cờ: {plaintext}")
                return
        except UnicodeDecodeError:
            # Bỏ qua nếu kết quả không phải là văn bản UTF-8 hợp lệ
            continue
            
    print("Không tìm thấy cờ. Có thể có lỗi trong logic.")

# Chạy trình giải
solve_ctf()