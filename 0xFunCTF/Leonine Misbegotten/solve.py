import base64
from hashlib import sha1

# Các hàm giải mã tương ứng
DECODE_SCHEMES = [
    base64.b16decode,
    base64.b32decode,
    base64.b64decode,
    base64.b85decode
]

# Đọc nội dung tệp output
with open("output", "rb") as f:
    current = f.read()

ROUNDS = 16

for i in range(ROUNDS):
    # 20 byte cuối là checksum SHA1 của dữ liệu vòng trước
    checksum = current[-20:]
    encoded_data = current[:-20]
    
    found = False
    for decode_func in DECODE_SCHEMES:
        try:
            # Thử giải mã
            decoded = decode_func(encoded_data)
            # Kiểm tra tính toàn vẹn bằng SHA1
            if sha1(decoded).digest() == checksum:
                current = decoded
                found = True
                print(f"[*] Round {i+1} reversed successfully.")
                break
        except Exception:
            continue
            
    if not found:
        print(f"[!] Failed to reverse round {i+1}")
        break

print("\nFlag của bạn là:", current.decode())