import sys
import itertools

def multiply_matrix_vector(matrix, vector):
    result = [0] * len(matrix)
    for i in range(len(matrix)):
        dot_product = 0
        for j in range(len(vector)):
            dot_product ^= matrix[i][j] & vector[j]
        result[i] = dot_product
    return result

def solve_linear_system(matrix, result_vector):
    solutions = []
    for i in range(16):
        v_candidate = [ (i >> 3) & 1, (i >> 2) & 1, (i >> 1) & 1, (i >> 0) & 1 ]
        if multiply_matrix_vector(matrix, v_candidate) == result_vector:
            # Trong trường hợp ma trận vẫn bị lỗi, có thể có nhiều lời giải
            # Chúng ta chỉ lấy lời giải đầu tiên tìm thấy
            return v_candidate
    return None

def is_printable(s):
    """Kiểm tra xem một chuỗi có chứa toàn ký tự in được, dễ đọc hay không."""
    # Bao gồm cả ký tự xuống dòng, tab, v.v. nhưng loại bỏ các ký tự điều khiển lạ
    return all(32 <= ord(c) < 127 or c in '\n\r\t' for c in s)

def decrypt_with_matrix(encrypted_data, matrix):
    decrypted_text = ""
    is_swapped_pair = False

    for i in range(0, len(encrypted_data), 2):
        byte1, byte2 = encrypted_data[i], encrypted_data[i+1]
        if is_swapped_pair:
            byte1, byte2 = byte2, byte1

        nibbles = []
        for byte_val in [byte1, byte2]:
            r_vector = [(byte_val >> (6 - j)) & 1 for j in range(7)]
            v_solution = solve_linear_system(matrix, r_vector)
            
            if v_solution is None:
                return None
            
            nibble = (v_solution[0] << 3) | (v_solution[1] << 2) | (v_solution[2] << 1) | v_solution[3]
            nibbles.append(nibble)

        original_char_code = (nibbles[0] << 4) | nibbles[1]
        decrypted_text += chr(original_char_code)
        is_swapped_pair = not is_swapped_pair
        
    return decrypted_text

# --- Chạy chương trình ---
if __name__ == "__main__":
    filename = "secret.enc" # Sử dụng file gốc của bạn
    
    try:
        with open(filename, 'rb') as f:
            encrypted_data = f.read()
    except FileNotFoundError:
        print(f"Lỗi: Không tìm thấy file '{filename}'.")
        sys.exit(1)

    if len(encrypted_data) % 2 != 0:
        print("Lỗi: File secret.enc có kích thước lẻ.")
        sys.exit(1)

    base_matrix = [
        [1, 1, 1, 0], [0, 1, 1, 1], [0, 0, 1, 1], [1, 0, 0, 1],
        [1, 1, 0, 1], [0, 0, 0, 0], [1, 1, 1, 1]
    ]

    print("Bắt đầu brute-force sửa lỗi ma trận...")
    
    found = False
    
    # Tạo tất cả 16 khả năng cho một hàng
    possible_rows = [[(i>>3)&1, (i>>2)&1, (i>>1)&1, (i>>0)&1] for i in range(16)]

    # Thử brute-force hàng r5 (chỉ số 5) và r3 (chỉ số 3)
    for r5_candidate in possible_rows[1:]: # Bỏ qua hàng [0,0,0,0]
        for r3_candidate in possible_rows:
            
            test_matrix = base_matrix[:]
            test_matrix[3] = r3_candidate
            test_matrix[5] = r5_candidate
            
            # Kiểm tra lại sự độc lập tuyến tính (một cách đơn giản)
            if (test_matrix[0][0]^test_matrix[1][0] == test_matrix[3][0] and
                test_matrix[0][1]^test_matrix[1][1] == test_matrix[3][1] and
                test_matrix[0][2]^test_matrix[1][2] == test_matrix[3][2] and
                test_matrix[0][3]^test_matrix[1][3] == test_matrix[3][3]):
                continue # Bỏ qua ma trận vẫn còn bị lỗi

            result = decrypt_with_matrix(encrypted_data, test_matrix)
            
            if result is not None and len(result) > 4 and is_printable(result):
                print("\n" + "=" * 40)
                print("ĐÃ TÌM THẤY LỜI GIẢI TIỀM NĂNG!")
                print(f"Ma trận có thể đúng:")
                for row in test_matrix:
                    print(row)
                print(f"\nFLAG: {result}")
                print("=" * 40)
                found = True
                # Không dừng lại, có thể có nhiều kết quả giả
    
    if not found:
        print("\nKhông tìm thấy lời giải nào hợp lệ sau khi thử tất cả các ma trận.")