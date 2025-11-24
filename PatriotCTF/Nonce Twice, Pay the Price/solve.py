import hashlib
import hmac
from ecdsa import SECP256k1, VerifyingKey
from Crypto.Cipher import AES

# --- 1. HÀM HKDF TỰ VIẾT (Chuẩn RFC 5869) ---
# Tránh phụ thuộc vào thư viện ngoài có thể gây lỗi
def hkdf_extract(salt, input_key_material):
    if salt is None or len(salt) == 0:
        salt = bytes([0] * 32) # Default salt for SHA256
    return hmac.new(salt, input_key_material, hashlib.sha256).digest()

def hkdf_expand(pseudo_random_key, info, length):
    t = b""
    okm = b""
    i = 0
    while len(okm) < length:
        i += 1
        t = hmac.new(pseudo_random_key, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
    return okm[:length]

def derive_hkdf_key(secret, salt=None, info=b''):
    prk = hkdf_extract(salt, secret)
    return hkdf_expand(prk, info, 32) # Lấy 32 bytes cho AES-256

# --- 2. DỮ LIỆU ---
PUB_KEY_PEM = """-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEL14ViCgtAY+8nxU4B4Uk0lCHMBdOFWr+X8eCgNb4+Xdt
yQiMeO3HSGRO3Xm8hZxBJDsGmY+QwkdQZW2NZ2UcPA==
-----END PUBLIC KEY-----"""

curve = SECP256k1
n = curve.order
r = int("288b415d6703ba7a2487681b10da092d991a2ef7d10de016daea4444523dc792", 16)
s1 = int("fc00f6d1c8e93beb4c983104f1991e6d1951aa729004b7a1e841f29d12797f4", 16)
z1 = int("9f9b697baa97445b19c6552e13b3a796ec9b76d6d95190a0c7fab01cce59b7fd", 16)
s2 = int("693ee365dd7307a44fddbdd81c0059b5b5f7ef419beee7aaada3c37798e270c5", 16)
z2 = int("465e2cf6b15b701b2d40cac239ab4d50388cd3e0ca54621cff58308f7c9a226b", 16)

def inverse_mod(a, m): return pow(a, -1, m)
k_int = ((z1 - z2) * inverse_mod(s1 - s2, n)) % n
d_int = (inverse_mod(r, n) * ((s1 * k_int) - z1)) % n

# Tính Shared Secret (S = k * Q)
vk = VerifyingKey.from_pem(PUB_KEY_PEM)
shared_point = vk.pubkey.point * k_int

# Tạo các dạng Shared Secret
# 1. Compressed (33 bytes) - Phổ biến nhất
prefix = b'\x02' if shared_point.y() % 2 == 0 else b'\x03'
S_comp = prefix + shared_point.x().to_bytes(32, 'big')

# 2. X-coordinate only (32 bytes)
S_x = shared_point.x().to_bytes(32, 'big')

# --- 3. DANH SÁCH KEY HKDF ---
keys = []

# Thử HKDF với S_compressed (Chuẩn ECIES)
keys.append(("HKDF(S_compressed)", derive_hkdf_key(S_comp)))
# Thử HKDF với S_x
keys.append(("HKDF(S_x)", derive_hkdf_key(S_x)))
# Thử HKDF với Nonce k
keys.append(("HKDF(k)", derive_hkdf_key(k_int.to_bytes(32, 'big'))))
# Thử HKDF với Private Key d
keys.append(("HKDF(d)", derive_hkdf_key(d_int.to_bytes(32, 'big'))))

# --- 4. GIẢI MÃ AES-GCM ---
try:
    with open("secret_blob.bin", "rb") as f:
        blob = f.read()
    
    # Cấu trúc GCM chuẩn: 12 Nonce + Cipher + 16 Tag
    nonce = blob[:12]
    ciphertext = blob[12:-16]
    tag = blob[-16:]
    
    print(f"[*] Đang thử giải mã {len(ciphertext)} bytes Ciphertext bằng AES-GCM với HKDF...\n")
    
    for name, key in keys:
        try:
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            
            print("\n" + "#"*60)
            print(f"🔥🔥🔥 BINGO! KEY FOUND: {name}")
            print(f"🚩 FLAG: {plaintext.decode()}")
            print("#"*60)
            break
        except ValueError:
            pass # Tag mismatch
        except Exception as e:
            print(f"[-] Error {name}: {e}")

    else:
        print("[-] Vẫn chưa tìm thấy. Nếu script này fail, hãy kiểm tra lại file secret_blob.bin.")

except FileNotFoundError:
    print("Thiếu file secret_blob.bin")