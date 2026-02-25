from pwn import *
import ctypes
import time

# Load thư viện C để dùng chung srand/rand
libc = ctypes.CDLL("libc.so.6")

# Khởi chạy file binary local
p = process('./guess_the_seed')

# Lấy thời gian hiện tại
seed = int(time.time())
libc.srand(seed)

# Tính toán 5 số
for i in range(5):
    target_num = libc.rand() % 1000
    p.sendline(str(target_num).encode())
    print(f"Sent: {target_num}")

# Nhận flag
print(p.recvall().decode())