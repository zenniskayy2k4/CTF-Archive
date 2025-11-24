from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# 1. Khôi phục Key từ các phần đã trích xuất
recipe = "Grandma's secret recipe: 1 cup of sugar, 2 cups of flour, 3 eggs, and a pinch of love."

parts = [
    recipe[0:1],      # offset 0, length 1
    recipe[34:35],    # offset 34, length 1
    recipe[15:19],    # offset 15, length 4
    recipe[42:49],    # offset 42, length 7
    recipe[72:77],    # offset 72, length 5
    recipe[6:10],     # offset 6, length 4
    recipe[82:89],    # offset 82, length 7
    recipe[2:3]       # offset 2, length 1
]

# Ghép các phần lại và chuyển thành bytes
key_30_bytes = "".join(parts).encode('utf-8')

# Thêm 2 byte null để đủ 32 byte
key = key_30_bytes + b'\x00\x00'

# 2. IV được hardcode trong chương trình
iv = b'1234567890123456'

# 3. Đọc file đã mã hóa
encrypted_file = "Grandmas_Secret_Baking_Family_Recipe.enc"
try:
    with open(encrypted_file, 'rb') as f:
        ciphertext = f.read()
except FileNotFoundError:
    print(f"Lỗi: Không tìm thấy file '{encrypted_file}'. Hãy đảm bảo file này nằm cùng thư mục với script.")
    exit()

# 4. Giải mã
try:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(ciphertext)
    
    # Gỡ bỏ padding (PKCS7)
    plaintext = unpad(decrypted_data, AES.block_size)
    
    print("="*50)
    print("GIẢI MÃ THÀNH CÔNG!")
    print("="*50)
    print("Nội dung công thức bí mật của bà là:")
    print(plaintext.decode('utf-8'))

except ValueError as e:
    print(f"Lỗi trong quá trình giải mã: {e}")
    print("Vui lòng kiểm tra lại Key, IV hoặc file mã hóa có thể đã bị hỏng.")
except Exception as e:
    print(f"Đã xảy ra lỗi không xác định: {e}")