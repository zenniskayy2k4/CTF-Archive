import base64
import re
from Crypto.Util.number import long_to_bytes

# 1. Đọc ciphertext
with open("ciphertext.txt", "r") as f:
    ct = int(f.read().strip())

# 2. Phân tích file PEM thủ công
with open("private_key.pem", "r") as f:
    pem_data = f.read()

# 3. Tìm các dòng có thông tin về n, e, d, p, q
# Một mẹo trong CTF RSA: Kiểm tra phần cuối của file, thường chứa các số quan trọng
lines = pem_data.split("\n")
intact_lines = [line for line in lines if "[#####REDACTED#####]" not in line]

# 4. Tìm kiếm thông tin có thể sử dụng từ các dòng còn nguyên vẹn
# Trong bài CTF kiểu này, thường một số thành phần của khóa còn nguyên
# và chúng ta có thể khôi phục các phần còn lại bằng các tính chất toán học của RSA

# 5. Một cách tiếp cận thay thế: 
# Sử dụng openssl để thử phân tích file PEM bị hỏng
import subprocess
try:
    result = subprocess.check_output(["openssl", "rsa", "-in", "private_key.pem", "-text", "-noout"], 
                                    stderr=subprocess.STDOUT, text=True)
    print("Openssl output:")
    print(result)
except subprocess.CalledProcessError as e:
    print("Không thể phân tích trực tiếp với openssl:", e.output)

# 6. Nếu bước 5 không hoạt động, bạn có thể thử sửa file PEM bằng cách thay thế các phần bị che
# với các giá trị trống hoặc dữ liệu mẫu, sau đó mới phân tích với openssl

# 7. Sau khi có đủ thông tin (n, d hoặc các tham số CRT), tiến hành giải mã:
# Ví dụ: nếu có d và n
# pt = pow(ct, d, n)
# message = long_to_bytes(pt)
# print("Flag:", message.decode())

# Thay thế phương pháp trên bằng các phân tích ASN.1 thủ công nếu cần thiết