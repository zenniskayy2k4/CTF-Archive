from pwn import *
import json

# Khởi chạy process
p = process('./curly-crab')

# 1. Tạo Payload lồng nhau 5 lớp (Recursive String)
# Đây là phần để vượt qua 5 vòng lặp `parse`
# Lớp trong cùng (kết quả sau 5 lần parse)
payload_1 = json.dumps({"CTF": 1, "pascal": "Core"})

# Bọc nó lại 5 lần vào trong trường 'pascal'
# Input -> Parse 1 -> Obj1 -> Parse 2 -> Obj2 -> ... -> Parse 5 -> Obj5
for _ in range(5):
    # json.dumps tự động escape chuỗi JSON bên trong
    payload_1 = json.dumps({"CTF": 1, "pascal": payload_1})

# 2. Tạo Payload kiểm tra cuối cùng (Final Check)
# Đây là phần để vượt qua hàm check cuối cùng sau vòng lặp
payload_2 = json.dumps({"CTF": 1, "pascal": "Win"})

# 3. Kết hợp cả hai payload
# Thêm dấu xuống dòng \n ở giữa để tách biệt rõ ràng (dù JSON parser có thể tự tách)
full_payload = payload_1.encode() + b'\n' + payload_2.encode()

# --- Gửi dữ liệu ---

# Đọc banner "Give me a JSONy flag!"
print(p.recvline())

print("Sending Combined Payload...")
# Gửi tất cả trong 1 lần để tránh lỗi BrokenPipe/Buffering
p.sendline(full_payload)

# Nhận và in Flag
try:
    # Đọc hết dữ liệu trả về
    print(p.recvall(timeout=2).decode(errors='ignore'))
except Exception as e:
    print(f"Error: {e}")

p.close()