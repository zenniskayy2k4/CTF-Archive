from hashlib import sha256
from Crypto.Cipher import AES
import string

def unpad(s):
    """Loại bỏ padding PKCS#7 một cách an toàn"""
    try:
        padding_len = s[-1]
        if padding_len > 16 or padding_len == 0:
            return b"[Invalid Padding Length]"
        if not all(c == padding_len for c in s[-padding_len:]):
            return b"[Invalid Padding Bytes]"
        return s[:-padding_len]
    except IndexError:
        return b"[Empty Decrypted String]"

# 1. Dữ liệu đã biết
# Vui lòng kiểm tra lại chuỗi này một cách cẩn thận nhất có thể
# Nó phải có chính xác 128 ký tự.
ct_hex = '75bd1089b2248540e3406aa014dc2b5add4fb83ffdc54d09beb878bbb0d42717e9cc6114311767dd9f3b8b070b359a1ac2eb695cd31f435680ea885e85690f89'
ct_bytes = bytes.fromhex(ct_hex)

x = 12500000
y = 8000000

print("--- Verifier Script ---")
print(f"Using x = {x}")
print(f"Using y = {y}")
print(f"Ciphertext length: {len(ct_bytes)} bytes")

# 2. Tạo key
key_tuple_str = str((x, y))
print(f"String to hash: '{key_tuple_str}'")

key = sha256(key_tuple_str.encode()).digest()
print(f"Generated Key (SHA256): {key.hex()}")

# 3. Giải mã
try:
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = cipher.decrypt(ct_bytes)
    print(f"Decrypted (raw hex): {decrypted.hex()}")
    
    # 4. Unpad và in kết quả
    unpadded = unpad(decrypted)
    print("--- RESULT ---")
    print(f"Flag: {unpadded.decode(errors='ignore')}")
    print("----------------")

except Exception as e:
    print(f"\nAn error occurred: {e}")