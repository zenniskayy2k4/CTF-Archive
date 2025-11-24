# Key 1 (3 byte) được tính từ vòng lặp "con sên", bắt đầu từ offset 0x2d
key1 = [0x01, 0x00, 0x00]

# Key 2 (6 byte) được gán cứng, bắt đầu từ offset 0x27
key2 = [
    0x12, 0x45, 0x78, 0xab, 0xcd, 0xef
]

# Dữ liệu mục tiêu (đã được mã hóa), bắt đầu từ offset 0x0
target_data = [
    0x65, 0x74, 0x0c, 0xd1, 0xbe, 0x81, 0x27, 0x2c, 0x14, 0xf5, 0xa9, 0xdc,
    0x7f, 0x74, 0x0e, 0x99, 0xbf, 0x96, 0x4c, 0x36, 0x14, 0x9a, 0xba, 0xb0,
    0x27, 0x23, 0x27, 0x99, 0xfb, 0xdb, 0x21, 0x75, 0x4f, 0x9c, 0xff, 0x8e,
    0x71, 0x38
]

# Chuẩn bị mảng byte để lưu trữ flag
flag = bytearray()

# Lặp qua từng byte của dữ liệu mục tiêu
for i in range(len(target_data)):
    # Lấy byte tương ứng từ mỗi key
    k1_byte = key1[i % 3]
    k2_byte = key2[i % 6]
    
    # Kết hợp 2 key bằng phép XOR
    combined_key_byte = k1_byte ^ k2_byte
    
    # Giải mã byte mục tiêu bằng key đã kết hợp
    decrypted_byte = target_data[i] ^ combined_key_byte
    flag.append(decrypted_byte)

# In ra flag đã được giải mã
print(f"Flag: {flag.decode('utf-8')}")