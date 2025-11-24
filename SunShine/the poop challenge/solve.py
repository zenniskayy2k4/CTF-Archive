# solve.py

# Định nghĩa các ký tự chúng ta đang tìm kiếm
POOP_EMOJI = '💩'
ZERO_WIDTH_SPACE = '\u200b'  # Sử dụng mã unicode để đảm bảo chính xác

# Hàm để chuyển đổi chuỗi nhị phân sang văn bản ASCII
def decode_binary_to_ascii(binary_str):
    ascii_string = ""
    # Lặp qua chuỗi nhị phân, mỗi lần lấy 8 ký tự (1 byte)
    for i in range(0, len(binary_str), 8):
        byte = binary_str[i:i+8]
        # Chỉ xử lý nếu nó là một byte hoàn chỉnh
        if len(byte) == 8:
            try:
                # Chuyển byte nhị phân sang số nguyên
                decimal_value = int(byte, 2)
                # Chuyển số nguyên sang ký tự ASCII
                ascii_string += chr(decimal_value)
            except ValueError:
                # Bỏ qua nếu có lỗi (ví dụ: byte không hợp lệ)
                pass
    return ascii_string

# --- Logic chính ---
try:
    # Mở file challenge và đọc nội dung.
    # Quan trọng: chỉ định encoding='utf-8' để đọc đúng các ký tự đặc biệt.
    with open('poop_challenge.txt', 'r', encoding='utf-8') as f:
        content = f.read()
except FileNotFoundError:
    print("Lỗi: Không tìm thấy file 'poop_challenge.txt'.")
    print("Hãy đảm bảo file này nằm cùng thư mục với script solve.py.")
    exit()

# Tạo chuỗi nhị phân dựa trên 2 giả thuyết
binary_string_1 = ""  # Giả thuyết 1: 💩=0, ZWSP=1
binary_string_2 = ""  # Giả thuyết 2: 💩=1, ZWSP=0

for char in content:
    if char == POOP_EMOJI:
        binary_string_1 += '0'
        binary_string_2 += '1'
    elif char == ZERO_WIDTH_SPACE:
        binary_string_1 += '1'
        binary_string_2 += '0'

# In kết quả
print("--- Thử giải mã với khả năng 1 (💩=0, ZWSP=1) ---")
flag1 = decode_binary_to_ascii(binary_string_1)
print(flag1)

print("\n--- Thử giải mã với khả năng 2 (💩=1, ZWSP=0) ---")
flag2 = decode_binary_to_ascii(binary_string_2)
print(flag2)