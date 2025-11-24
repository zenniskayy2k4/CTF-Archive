import json
import base64
import time
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

def b64url_encode(data):
    """Mã hóa base64 an toàn cho URL, loại bỏ ký tự '='."""
    return base64.urlsafe_b64encode(data).replace(b'=', b'')

# Đọc khóa riêng từ file private.pem mà chúng ta đã tạo
try:
    with open("private.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )
except FileNotFoundError:
    print("Lỗi: Không tìm thấy file 'private.pem'. Hãy chắc chắn bạn đã chạy script 'recover_key.py' thành công.")
    exit()

# Tạo payload để trở thành VIP. Các trường phải khớp với những gì
# hàm verify_token trong chương trình chatbot mong đợi.
payload = {
    "user": "zenniskayy",  # Tên người dùng có thể tùy ý
    "role": "VIP",        # Đây là trường quan trọng nhất!
    "expiry": int(time.time()) + 3600  # Đặt thời gian hết hạn là 1 giờ sau
}

# Chuyển payload từ dạng dict sang chuỗi JSON, rồi sang bytes
# separators=(',', ':') để loại bỏ khoảng trắng, giống như các thư viện chuẩn thường làm
payload_bytes = json.dumps(payload, separators=(',', ':')).encode('utf-8')

# Dùng khóa riêng để ký vào payload_bytes
# Các tham số padding và hash phải khớp với những gì hàm verify_token sử dụng
signature = private_key.sign(
    payload_bytes,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

# Mã hóa payload và chữ ký sang định dạng Base64URL
payload_b64 = b64url_encode(payload_bytes)
sig_b64 = b64url_encode(signature)

# Ghép chúng lại thành token theo định dạng: [payload].[signature]
token = payload_b64.decode('utf-8') + '.' + sig_b64.decode('utf-8')

print("--- Your VIP Token ---")
print(token)
print("\n[+] Copy the token above and paste it into the chatbot's upgrade prompt.")