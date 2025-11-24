TARGET = [
    0x5A,0x3D,0x5B,0x9C,0x98,0x73,0xAE,0x32,0x25,0x47,
    0x48,0x51,0x6C,0x71,0x3A,0x62,0xB8,0x7B,0x63,0x57,
    0x25,0x89,0x58,0xBF,0x78,0x34,0x98,0x71,0x68,0x59
]

XOR_KEY = [0x42, 0x73, 0x21, 0x69, 0x37]
MAGIC_ADD = 0x2A
FLAG_LEN = 30

# Chuyển TARGET sang list để dễ xử lý
buffer = list(TARGET)

# print("[-] Đang giải mã...")

# 1. Đảo ngược Bước 4: XOR với vị trí (index)
# Forward: buffer[i] ^= i
# Reverse: buffer[i] ^= i
for i in range(FLAG_LEN):
    buffer[i] ^= i

# 2. Đảo ngược Bước 3: Trừ hằng số Magic
# Forward: buffer[i] = (buffer[i] + MAGIC_ADD) % 256
# Reverse: buffer[i] = (buffer[i] - MAGIC_ADD) % 256
for i in range(FLAG_LEN):
    buffer[i] = (buffer[i] - MAGIC_ADD) & 0xFF # & 0xFF để xử lý số âm

# 3. Đảo ngược Bước 2: Hoán đổi cặp byte
# Forward: Swap(i, i+1)
# Reverse: Swap(i, i+1)
for i in range(0, FLAG_LEN, 2):
    temp = buffer[i]
    buffer[i] = buffer[i+1]
    buffer[i+1] = temp

# 4. Đảo ngược Bước 1: XOR với Key xoay vòng
# Forward: buffer[i] ^= XOR_KEY[i % 5]
# Reverse: buffer[i] ^= XOR_KEY[i % 5]
for i in range(FLAG_LEN):
    buffer[i] ^= XOR_KEY[i % 5]

# Chuyển mảng byte thành chuỗi ký tự
flag = ''.join(chr(b) for b in buffer)

print(f"Flag: {flag}")