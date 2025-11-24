# 1. Chuỗi hex đã được trích xuất từ hình ảnh của bạn
hex_string = "5e 54 43 51 4c 52 4f 43 52 59 44 5e 58 59 44 68 5a 5e 50 5f 43 68 5d 42 44 43 68 44 42 54 5c 4a"

# 2. Tách chuỗi thành các mã hex
hex_codes = hex_string.split()

# 3. Chuyển đổi chuỗi hex thành một chuỗi bytes (dữ liệu đã mã hóa)
encrypted_bytes = bytearray()
for code in hex_codes:
    encrypted_bytes.append(int(code, 16))

# 4. Key giải mã chúng ta đã tìm thấy
key = 0x37

# 5. Giải mã bằng cách XOR mỗi byte với key
decrypted_bytes = bytearray()
for byte in encrypted_bytes:
    decrypted_bytes.append(byte ^ key)

# 6. Chuyển đổi chuỗi bytes đã giải mã thành văn bản và in ra
flag = decrypted_bytes.decode('utf-8')

print(f"Flag: {flag}")