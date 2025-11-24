import base64

# 1. Chuỗi Base64 được mã hóa cứng từ mã nguồn (Bước 2)
encrypted_b64 = "KXgmYHMADxsV8uHiuPPB3w=="

# Giải mã Base64 chuỗi này
encrypted_data = base64.b64decode(encrypted_b64)

# 2. Tạo lại khóa XOR động (Bước 1)
# Công thức: key[i] = (i * 7 + 66)
# Chúng ta chỉ cần 16 byte đầu tiên vì dữ liệu mã hóa dài 16 byte.
xor_key = bytearray()
for i in range(len(encrypted_data)):
    byte_value = (i * 7 + 66) & 0xFF
    xor_key.append(byte_value)

# 3. Thực hiện giải mã bằng phép toán XOR (Bước 3)
decrypted_data = bytearray()
for i in range(len(encrypted_data)):
    decrypted_byte = encrypted_data[i] ^ xor_key[i]
    decrypted_data.append(decrypted_byte)

# Chuyển kết quả sang dạng chuỗi để đọc
killswitch_domain = decrypted_data.decode('utf-8')

# In ra kết quả
print(f"Dữ liệu mã hóa (hex): {encrypted_data.hex()}")
print(f"Khóa XOR được tạo (hex): {xor_key.hex()}")
print(f"Kết quả giải mã (hex): {decrypted_data.hex()}")
print("-" * 30)
print(f"Killswitch Domain: {killswitch_domain}")