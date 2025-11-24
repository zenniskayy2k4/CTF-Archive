from pwn import *
import binascii

# Thông tin kết nối
HOST = 'chal.sunshinectf.games'
PORT = 25403

# Kết nối đến server
try:
    r = remote(HOST, PORT)
except Exception as e:
    print(f"Không thể kết nối đến {HOST}:{PORT}: {e}")
    exit()

# Bỏ qua các dòng giới thiệu
r.recvuntil(b'== BEGINNING TRANSMISSION ==\n\n')


ciphertexts = []
print("Đang thu thập các bản mã...")
for i in range(50):
    line = r.recvline().strip()
    if not line:
        break
    ciphertexts.append(binascii.unhexlify(line))

print(f"Đã thu thập {len(ciphertexts)} bản mã.")
r.close()

# Khối bản rõ đầu tiên đã biết (16 byte)
known_plaintext_block = b"Greetings, Earth"

# Tái tạo lại chuỗi keystream
full_keystream = b''
for ct in ciphertexts:
    # Lấy khối bản mã đầu tiên của mỗi ciphertext
    first_block_ct = ct[:16]
    
    # Khôi phục keystream block tương ứng
    keystream_block = xor(first_block_ct, known_plaintext_block)
    
    # Thêm vào chuỗi keystream hoàn chỉnh
    full_keystream += keystream_block

# Lấy bản mã đầu tiên (Ciphertext 0) để giải mã
first_ciphertext = ciphertexts[0]

# Đảm bảo keystream đủ dài
# (Không thực sự cần thiết nếu chúng ta lấy đủ ciphertext, nhưng để chắc chắn)
full_keystream = full_keystream[:len(first_ciphertext)]

# Giải mã
decrypted_message = xor(first_ciphertext, full_keystream)

# In kết quả
print("\n--- TIN NHẮN ĐÃ GIẢI MÃ ---")
# Dùng errors='ignore' để xử lý các byte không hợp lệ có thể xuất hiện
print(decrypted_message.decode(errors='ignore'))