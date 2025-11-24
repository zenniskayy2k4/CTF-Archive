# Đọc 6 byte đầu và 6 byte cuối để tạo thành khóa
with open('forward.bin', 'rb') as f_forward:
    forward_bytes = f_forward.read()

with open('back.bin', 'rb') as f_back:
    back_bytes = f_back.read()

# Ghép lại thành một khóa dài 12 byte
key = forward_bytes + back_bytes
key_length = len(key)

# Đọc nội dung của file flag đã bị mã hóa
with open('flag.ENCRYPTED', 'rb') as f_encrypted:
    encrypted_data = f_encrypted.read()

# Chuẩn bị để lưu kết quả giải mã
decrypted_bytes = bytearray()

# Thực hiện giải mã bằng repeating key XOR
for i in range(len(encrypted_data)):
    # Lấy byte từ dữ liệu mã hóa
    encrypted_byte = encrypted_data[i]
    # Lấy byte tương ứng từ khóa (lặp lại khóa nếu cần)
    key_byte = key[i % key_length]
    # XOR và thêm kết quả vào
    decrypted_bytes.append(encrypted_byte ^ key_byte)

# In ra flag cuối cùng
print(decrypted_bytes.decode())