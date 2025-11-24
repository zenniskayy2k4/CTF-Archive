from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# Dữ liệu từ file output.txt
iv0_hex = '4858c64be12fbb05c648d6ef4be134a1'
ct0_hex = 'f865533a29fa083996223e60d0b4a62be1e7cfac3ef1981ed53564b9eb2e2b36d28bfcaf6d656deb365e26c6d89782f9abd82b99f75a7b72c564b48a2598577492c459e089c798bf02c7fb621930ef84'
iv1_hex = 'ef73d8fa5ce9521495abcea79f6a2d4b'
ct1_hex = 'bd669aa9cb3ae0a46b46633eccd38a81c9e6c102f34d0809c3aa7cf6b824615cf9534275b23b97ce5a9efe039985dbcf5e3edc8266ff58c3629f40fe277e460c'

# Chuyển đổi từ hex sang bytes
key0 = bytes.fromhex(iv0_hex)
ct0 = bytes.fromhex(ct0_hex)
key1 = bytes.fromhex(iv1_hex)
ct1 = bytes.fromhex(ct1_hex)

# Plaintext đã biết
pt0 = b"One documentation a day keeps the bugs away or whatever my doctor used to say"

BLOCK_SIZE = 16

# --- Bước 1 & 2: Tìm IV bị tái sử dụng ---

# Lấy khối đầu tiên
pt0_block1 = pt0[:BLOCK_SIZE]
ct0_block1 = ct0[:BLOCK_SIZE]

# Tính E(key0, IV_reused) = pt0_block1 XOR ct0_block1
# (Phép XOR có thể áp dụng cho từng byte)
encrypted_iv = bytes([p ^ c for p, c in zip(pt0_block1, ct0_block1)])

# Tạo một cipher AES để giải mã (ECB mode là đủ để giải mã 1 khối)
decipher0 = AES.new(key0, AES.MODE_ECB)

# Tìm IV_reused = D(key0, encrypted_iv)
iv_reused = decipher0.decrypt(encrypted_iv)

print(f"[*] Found reused IV: {iv_reused.hex()}")

# --- Bước 3, 4 & 5: Giải mã flag ---

# Tạo một cipher AES để mã hóa với key1
encipher1 = AES.new(key1, AES.MODE_ECB)

decrypted_flag = b""
previous_ct_block = iv_reused # Đối với khối đầu tiên, đầu vào là IV

# Lặp qua từng khối của ciphertext của flag
for i in range(0, len(ct1), BLOCK_SIZE):
    current_ct_block = ct1[i:i+BLOCK_SIZE]
    
    # Tạo keystream: E(key1, previous_block)
    keystream = encipher1.encrypt(previous_ct_block)
    
    # Giải mã khối hiện tại: P_N = C_N XOR Keystream
    decrypted_block = bytes([c ^ k for c, k in zip(current_ct_block, keystream)])
    decrypted_flag += decrypted_block
    
    # Khối ciphertext hiện tại sẽ là đầu vào cho khối tiếp theo
    previous_ct_block = current_ct_block

# Loại bỏ padding ở cuối
try:
    flag = unpad(decrypted_flag, BLOCK_SIZE)
except ValueError:
    # Nếu không có padding, in ra kết quả thô
    flag = decrypted_flag

print(f"\n[+] Flag: {flag.decode()}")