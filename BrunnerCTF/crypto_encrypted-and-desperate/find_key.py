from itertools import cycle

# 16 byte đầu tiên của một file PNG tiêu chuẩn (magic number + IHDR chunk header)
png_header = bytes([
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a,
    0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52
])

# Đọc 16 byte đầu tiên từ file đã bị mã hóa
encrypted_header = b''
with open("./recipes/b4.gif.enc", "rb") as f:
    encrypted_header = f.read(16)

# Khôi phục khóa bằng cách XOR bản rõ đã biết với bản mã
key = bytes(p ^ c for p, c in zip(png_header, encrypted_header))

print(f"Recovered Key (bytes): {key}")
print(f"Recovered Key (hex):  {key.hex()}")