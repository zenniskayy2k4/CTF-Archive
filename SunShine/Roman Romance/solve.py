# Mở file đã mã hóa ở chế độ đọc byte ('rb')
with open('enc.txt', 'rb') as f_enc:
    encrypted_data = f_enc.read()

# Tạo một list byte để lưu trữ dữ liệu đã giải mã
decrypted_data = bytearray()

# Lặp qua từng byte trong dữ liệu đã mã hóa
for byte in encrypted_data:
    # Thực hiện phép toán ngược: trừ đi 1
    # Dùng (byte - 1) & 0xFF để đảm bảo kết quả luôn là một byte hợp lệ (0-255)
    decrypted_byte = (byte - 1) & 0xFF
    decrypted_data.append(decrypted_byte)

# In kết quả đã giải mã ra màn hình
# decode('utf-8') để chuyển từ byte sang chuỗi ký tự có thể đọc được
print(decrypted_data.decode('utf-8'))