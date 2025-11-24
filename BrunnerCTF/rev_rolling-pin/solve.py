# Hàm xoay phải (rotr) cho một byte (8-bit)
def rotr(x, k):
    """Xoay phải các bit của byte x đi k vị trí."""
    k = k & 7  # Đảm bảo k nằm trong khoảng 0-7, tương đương k % 8
    # Phép toán xoay phải:
    # (x >> k) -> Dịch các bit sang phải k lần
    # (x << (8 - k)) -> Dịch các bit sang trái (8-k) lần để lấy các bit tràn qua
    # & 0xFF -> Đảm bảo kết quả là một byte
    return ((x >> k) | (x << (8 - k))) & 0xFF

# Dữ liệu của mảng 'baked' trích xuất từ file binary
baked = [
    0x62, 0xe4, 0xd5, 0x73, 0xe6, 0xac, 0x9c, 0xbd,
    0x72, 0x60, 0xd1, 0xa1, 0x47, 0x66, 0xd7, 0x3a,
    0x68, 0x66, 0x7d, 0x23, 0x03, 0xae, 0xd9, 0x34,
    0x7d
]

# Khởi tạo chuỗi kết quả
flag = []

# Lặp qua tất cả 25 byte (độ dài 0x19)
for i in range(len(baked)):
    # Lấy giá trị byte từ mảng baked
    baked_char = baked[i]
    
    # Số bit cần xoay (ngược lại)
    rotate_amount = i & 7
    
    # Thực hiện thao tác ngược: xoay phải
    original_char_code = rotr(baked_char, rotate_amount)
    
    # Chuyển mã số thành ký tự
    flag.append(chr(original_char_code))

# Nối các ký tự lại thành chuỗi hoàn chỉnh và in ra
result = "".join(flag)
print(f"Đáp án cần tìm là: {result}")