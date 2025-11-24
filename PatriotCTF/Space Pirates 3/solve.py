# Dữ liệu Target từ file Go
TARGET = [
    0x60, 0x6D, 0x5D, 0x97, 0x2C, 0x04, 0xAF, 0x7C, 0xE2, 0x9E,
    0x77, 0x85, 0xD1, 0x0F, 0x1D, 0x17, 0xD4, 0x30, 0xB7, 0x48,
    0xDC, 0x48, 0x36, 0xC1, 0xCA, 0x28, 0xE1, 0x37, 0x58, 0x0F
]

XOR_KEY = [0xC7, 0x2E, 0x89, 0x51, 0xB4, 0x6D, 0x1F]
ROTATION_PATTERN = [7, 5, 3, 1, 6, 4, 2, 0]
MAGIC_SUB = 0x93
CHUNK_SIZE = 6
FLAG_LEN = 30

# Hàm xoay phải bit (Rotate Right) cho 8-bit byte
# Để đảo ngược Rotate Left
def rotate_right(val, n):
    n = n % 8
    return ((val >> n) | (val << (8 - n))) & 0xFF

# Copy buffer để xử lý
buffer = list(TARGET)

print("[-] Đang giải mã Vault Level 3...")

# 1. Đảo ngược Bước 6: XOR với (position^2 + position)
# Forward: buffer[i] ^= (i*i + i)
# Reverse: buffer[i] ^= (i*i + i)
for i in range(FLAG_LEN):
    pos_val = ((i * i) + i) % 256
    buffer[i] ^= pos_val

# 2. Đảo ngược Bước 5: Đảo ngược từng chunk 6 byte
# Forward: Reverse chunk
# Reverse: Reverse chunk
for i in range(0, FLAG_LEN, CHUNK_SIZE):
    chunk = buffer[i : i + CHUNK_SIZE]
    buffer[i : i + CHUNK_SIZE] = chunk[::-1]

# 3. Đảo ngược Bước 4: Cộng lại hằng số Magic
# Forward: buffer[i] -= MAGIC_SUB
# Reverse: buffer[i] += MAGIC_SUB
for i in range(FLAG_LEN):
    buffer[i] = (buffer[i] + MAGIC_SUB) & 0xFF

# 4. Đảo ngược Bước 3: Hoán đổi cặp byte
# Forward: Swap(i, i+1)
# Reverse: Swap(i, i+1)
for i in range(0, FLAG_LEN - 1, 2):
    buffer[i], buffer[i+1] = buffer[i+1], buffer[i]

# 5. Đảo ngược Bước 2: Xoay bit (Rotate Right)
# Forward: Rotate Left theo pattern
# Reverse: Rotate Right theo pattern
for i in range(FLAG_LEN):
    rot_amount = ROTATION_PATTERN[i % len(ROTATION_PATTERN)]
    buffer[i] = rotate_right(buffer[i], rot_amount)

# 6. Đảo ngược Bước 1: XOR Key
# Forward: buffer[i] ^= XOR_KEY
# Reverse: buffer[i] ^= XOR_KEY
for i in range(FLAG_LEN):
    buffer[i] ^= XOR_KEY[i % len(XOR_KEY)]

# Chuyển thành chuỗi
flag = "".join(chr(b) for b in buffer)

print("\n🏴‍☠️  VAULT UNLOCKED! 🏴‍☠️")
print(f"Flag: {flag}")