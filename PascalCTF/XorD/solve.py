import random

# Nội dung từ file output.txt
hex_output = "cb35d9a7d9f18b3cfc4ce8b852edfaa2e83dcd4fb44a35909ff3395a2656e1756f3b505bf53b949335ceec1b70e0"

# Chuyển đổi hex string thành bytes
encrypted_bytes = bytes.fromhex(hex_output)

# Đặt seed giống như trong source code đề bài
random.seed(1337)

decrypted_chars = []

# Duyệt qua từng byte đã mã hóa
for byte in encrypted_bytes:
    # Sinh ra số random y hệt lúc mã hóa
    key = random.randint(0, 255)
    
    # XOR ngược lại để lấy ký tự gốc (A ^ B = C => C ^ B = A)
    original_char = byte ^ key
    decrypted_chars.append(chr(original_char))

# In ra flag
flag = "".join(decrypted_chars)
print(f"Flag: {flag}")