import hashlib
import csv
import traceback

# Import các thư viện cần thiết cho hàm giải mã
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

def decrypt_with_bug(data: str, nonce: str, password: str, hash_salt: str, key_salt: str) -> str:
    """
    Đây là phiên bản MÔ PHỎNG LẠI LỖI của hàm encrypt_data.
    Lỗi nằm ở việc sử dụng `hash_salt` cho cả hai bước.
    """
    argon2_hash = hash_secret_raw(
        secret=password.encode(),
        salt=bytes.fromhex(hash_salt),
        time_cost=5, memory_cost=262144, parallelism=4, hash_len=64, type=Type.ID
    )
    
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        # !! ĐÂY CHÍNH LÀ LỖI !! Lập trình viên đã dùng lại hash_salt thay vì key_salt
        salt=bytes.fromhex(hash_salt),
        info=b'user-data-encryption'
    )
    key = hkdf.derive(argon2_hash)
    
    aesgcm = AESGCM(key)
    # Chỉ thực hiện giải mã
    return aesgcm.decrypt(bytes.fromhex(nonce), bytes.fromhex(data), None).hex()

# ==============================================================================
# BƯỚC CUỐI: GIẢI MÃ VỚI LOGIC ĐÚNG
# ==============================================================================

print("[+] Bước 1: Sử dụng các giá trị đã được xác thực")
BRUNNER_PASSWORD = 'e9d8' 
print(f"    - Pepper: 'e9d8'")
print(f"    - Mật khẩu của Brunner: '{BRUNNER_PASSWORD}'\n")

print("[+] Bước 2: Giải mã công thức bằng cách mô phỏng lại lỗi của lập trình viên...")

brunner_data = {}
with open('peppernut_recipes.csv', mode='r') as csv_file:
    csv_reader = csv.DictReader(csv_file)
    for row in csv_reader:
        if row['username'] == 'Brunner':
            brunner_data = row
            break

try:
    decrypted_recipe_hex = decrypt_with_bug(
        data=brunner_data['encrypted_recipe'],
        nonce=brunner_data['nonce'],
        password=BRUNNER_PASSWORD,
        hash_salt=brunner_data['hash_salt'],
        key_salt=brunner_data['key_salt'] # Tham số này thực ra không được dùng trong hàm bị lỗi
    )

    decrypted_recipe_text = bytes.fromhex(decrypted_recipe_hex).decode('utf-8')

    print("    [!] THÀNH CÔNG! Lỗi đã được tái hiện và dữ liệu đã được giải mã.")
    print("-" * 50)
    print(decrypted_recipe_text)
    print("-" * 50)

except Exception as e:
    print(f"\n    [-] Vẫn gặp lỗi: {repr(e)}. Điều này không nên xảy ra.")
    traceback.print_exc()