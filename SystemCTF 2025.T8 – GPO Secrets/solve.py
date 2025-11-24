import base64
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import unpad

base64_ciphertext = "w/BX481MVteTsqfzuzUBTe+BcSG+2dGSr4Csbmzh3+T9zczDBa4p32ZRKzFCgE4aElN93L7MO99D0izyKuBj6w=="

# GIẢ THUYẾT MỚI
password = "{A8FC5AD0-FE49-4107-9D2D-5BDD48AD198D}"
ITERATIONS = 100000  # THỬ LẠI VỚI 100,000 VÒNG

SALT_SIZE = 16
IV_SIZE = 16
KEY_SIZE_BYTES = 32

try:
    encrypted_data_bytes = base64.b64decode(base64_ciphertext)
    salt = encrypted_data_bytes[0:SALT_SIZE]
    iv = encrypted_data_bytes[SALT_SIZE : SALT_SIZE + IV_SIZE]
    ciphertext = encrypted_data_bytes[SALT_SIZE + IV_SIZE :]
    
    print(f"[*] Thử nghiệm với mật khẩu: {password}")
    print(f"[*] Thử nghiệm với số vòng lặp: {ITERATIONS}")
    key = PBKDF2(password, salt, dkLen=KEY_SIZE_BYTES, count=ITERATIONS)
    print(f"[*] Khóa đã tạo (hex): {key.hex()}")

    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_padded = cipher.decrypt(ciphertext)
    
    decrypted = unpad(decrypted_padded, AES.block_size)
    flag3 = decrypted.decode('utf-8')

    print("\n" + "="*40)
    print(f"🎉 THÀNH CÔNG! FLAG 3: {flag3}")
    print("="*40)

except Exception as e:
    print(f"\n[!] Vẫn lỗi: {e}")