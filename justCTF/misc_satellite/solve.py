import struct

# Hàm giải mã một khối 8-byte bằng thuật toán TEA
def decrypt_tea(block, key):
    # Khối 64-bit được chia thành hai số nguyên 32-bit (v0, v1)
    # L: little-endian, I: unsigned 32-bit integer
    v0, v1 = struct.unpack('<II', block)
    
    # Khóa 128-bit được chia thành bốn số nguyên 32-bit (k0, k1, k2, k3)
    k0, k1, k2, k3 = key
    
    # Hằng số delta và sum ban đầu cho 32 vòng lặp
    delta = 0x9e3779b9
    sum = delta * 32
    
    # Vòng lặp giải mã chính (32 vòng)
    for _ in range(32):
        v1 -= ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3)
        v1 &= 0xFFFFFFFF # Đảm bảo v1 là số 32-bit
        
        v0 -= ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1)
        v0 &= 0xFFFFFFFF # Đảm bảo v0 là số 32-bit
        
        sum -= delta
        sum &= 0xFFFFFFFF # Đảm bảo sum là số 32-bit

    # Ghép hai số nguyên 32-bit lại thành khối 8-byte
    return struct.pack('<II', v0, v1)

# --- DỮ LIỆU CỦA BẠN ---

# 1. Dán chuỗi hex bạn trích xuất từ Wireshark vào đây
ciphertext_hex = "5771D410CFFE844D24B50FCBBBDC1973A7A935E5C3468242950DFCCE94794B067F876A215D96EE09"

# 2. Khóa chúng ta đã tìm thấy
key = [0x12345678, 0x9abcdef0, 0x11111111, 0x22222222]


# --- LOGIC CHÍNH ---

# Chuyển đổi chuỗi hex thành dữ liệu bytes
try:
    ciphertext_bytes = bytes.fromhex(ciphertext_hex)
except ValueError:
    print("Lỗi: Chuỗi hex không hợp lệ. Hãy kiểm tra lại.")
    exit()

# Kiểm tra xem độ dài có phải là bội số của 8 không
if len(ciphertext_bytes) % 8 != 0:
    print("Lỗi: Độ dài của dữ liệu đã giải mã hex không phải là bội số của 8.")
    exit()
    
decrypted_data = b''
# Lặp qua từng khối 8 byte của ciphertext
for i in range(0, len(ciphertext_bytes), 8):
    block = ciphertext_bytes[i:i+8]
    decrypted_block = decrypt_tea(block, key)
    decrypted_data += decrypted_block

# In kết quả, loại bỏ các byte padding rác ở cuối nếu có
try:
    # Thường thì flag sẽ ở định dạng ASCII/UTF-8
    print("Đã giải mã thành công!")
    print("Flag:", decrypted_data.decode('utf-8').strip())
except UnicodeDecodeError:
    print("Không thể giải mã thành chuỗi UTF-8. Dữ liệu sau khi giải mã (dạng bytes):")
    print(decrypted_data)