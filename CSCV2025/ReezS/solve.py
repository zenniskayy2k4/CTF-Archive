import hashlib

# Dữ liệu thật được giấu trong phần .rdata
real_data_part1 = [
    0x9a, 0xcb, 0xcf, 0x9e, 0x98, 0xc9, 0xc8, 0x9d,
    0xc9, 0x98, 0x99, 0x9b, 0x9c, 0xcf, 0x9f, 0x93
]

real_data_part2 = [
    0xcf, 0xcf, 0xcf, 0x9d, 0xcf, 0x98, 0x9a, 0x99,
    0x9b, 0x9a, 0x98, 0xcb, 0x9d, 0x9d, 0x9d, 0x9f
]

# Kết hợp hai phần dữ liệu thật
full_real_data = real_data_part1 + real_data_part2

# Key XOR được "nhá hàng" trong hàm bẫy
xor_key = 0xaa

# Bắt đầu giải mã
real_flag_content = ""
for byte_value in full_real_data:
    decrypted_char = chr(byte_value ^ xor_key)
    real_flag_content += decrypted_char

print("Flag content:", real_flag_content)
print("-" * 20)
print(f"CSCV2025{{{real_flag_content}}}")