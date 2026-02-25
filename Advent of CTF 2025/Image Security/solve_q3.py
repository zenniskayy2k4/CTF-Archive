import base64

encoded_str = "AEUBzgKoA6cEVAVBBtQIoQkRC9QNaw9kE8QQ0xIuFvkZMBy7GsobGRwhHnk="
p = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97]
k = 165

# Giải mã Base64 ra chuỗi bytes
data_bytes = base64.b64decode(encoded_str)

ans = ""

# 2. Duyệt qua từng cặp 2 bytes
# i sẽ nhảy 0, 2, 4, 6...
for i in range(0, len(data_bytes), 2):
    # Lấy 2 bytes hiện tại
    chunk = data_bytes[i:i+2]
    
    # Chuyển 2 bytes về số nguyên (Big Endian như trong code gốc)
    x = int.from_bytes(chunk, 'big')
    
    # Tính vị trí index của ký tự (để lấy số nguyên tố m)
    char_index = i // 2
    m = p[char_index % len(p)]
    
    # x = (a * m) ^ k
    # => a * m = x ^ k
    # => a = (x ^ k) / m
    val_after_xor = x ^ k
    ascii_val = val_after_xor // m
    
    ans += chr(ascii_val)

print("Decoded message:", ans)