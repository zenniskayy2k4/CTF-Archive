# Các giá trị hex đã cho
h1_hex = "37dcb292030faa90d07eec17e3b1c6d8daf94c35d4c9191a5e1e"
h2_hex = "c1545756687e7573db23aa1c3452a098b71a7fbf0fddddde5fc1"
h3_hex = "04ee9855208a2cd59091d04767ae47963170d1660df7f56f5faf"

# Chuyển đổi chuỗi hex thành số nguyên
h1_int = int(h1_hex, 16)
h2_int = int(h2_hex, 16)
h3_int = int(h3_hex, 16)

# Thực hiện phép XOR
flag_int = h3_int ^ h1_int ^ h2_int

# Chuyển kết quả số nguyên trở lại dạng hex để xem
flag_hex = hex(flag_int)
print(f"Flag (dạng hex): {flag_hex}")

# Để có được flag dạng text, chuyển số nguyên thành bytes rồi decode
# 'big' để đảm bảo thứ tự byte đúng
# (flag_int.bit_length() + 7) // 8 để tính số byte cần thiết
flag_bytes = flag_int.to_bytes((flag_int.bit_length() + 7) // 8, 'big')
flag_text = flag_bytes.decode()

print(f"Flag (dạng text): {flag_text}")