import json
import base64
import time
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, utils

def b64url_encode(data):
    return base64.urlsafe_b64encode(data).replace(b'=', b'')

try:
    with open("private.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )
except FileNotFoundError:
    print("Lỗi: Không tìm thấy file 'private.pem'.")
    exit()

payload = {
    "user": "zenniskayy",
    "role": "VIP",
    "expiry": int(time.time()) + 3600
}
payload_bytes = json.dumps(payload, separators=(',', ':')).encode('utf-8')

# --- SỬA LẠI PADDING CHO ĐÚNG VỚI BYTECODE ---
# Dùng padding.PKCS1v15() thay vì PSS
signature = private_key.sign(
    payload_bytes,
    padding.PKCS1v15(),
    hashes.SHA256()
)

payload_b64 = b64url_encode(payload_bytes)
sig_b64 = b64url_encode(signature)

token = payload_b64.decode('utf-8') + '.' + sig_b64.decode('utf-8')

print("--- Your CORRECT VIP Token ---")
print(token)
print("\n[+] This token is generated with the correct padding. Try it now!")