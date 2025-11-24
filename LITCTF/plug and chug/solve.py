from pwn import *
import math

# Địa chỉ server, thay đổi nếu cần
HOST = "litctf.org"
PORT = 31789

p = remote(HOST, PORT)

min_x = 998244353

# --- Lấy K1 ---
x1, x2 = min_x, min_x + 1
x3 = x1 + x2
p.sendlineafter(b"guess): ", str(x1).encode())
r1 = int(p.recvline().strip())
p.sendlineafter(b"guess): ", str(x2).encode())
r2 = int(p.recvline().strip())
p.sendlineafter(b"guess): ", str(x3).encode())
r3 = int(p.recvline().strip())
K1 = abs(r1 * r2 - r3) # Dùng abs để đảm bảo K1 dương

# --- Lấy K2 ---
x4, x5 = min_x + 2, min_x + 3
x6 = x4 + x5
p.sendlineafter(b"guess): ", str(x4).encode())
r4 = int(p.recvline().strip())
p.sendlineafter(b"guess): ", str(x5).encode())
r5 = int(p.recvline().strip())
p.sendlineafter(b"guess): ", str(x6).encode())
r6 = int(p.recvline().strip())
K2 = abs(r4 * r5 - r6) # Dùng abs để đảm bảo K2 dương

# --- Tính n_candidate và hiệu chỉnh ---
n_candidate = math.gcd(K1, K2)
print(f"\nFound candidate n: {n_candidate}")
print(f"Bit length of candidate: {n_candidate.bit_length()}")

# === PHẦN SỬA LỖI QUAN TRỌNG ===
# Nếu độ dài bit lớn hơn 1024, ta cần loại bỏ các thừa số phụ
n_final = n_candidate
while n_final.bit_length() > 1024:
    # Trường hợp phổ biến nhất là thừa số 2
    if n_final % 2 == 0:
        n_final //= 2
    else:
        # Bạn có thể thử các số nguyên tố nhỏ khác nếu cần
        # nhưng thường chỉ cần chia cho 2 là đủ
        break 

print(f"\nFinal n after correction: {n_final}")
print(f"Final bit length: {n_final.bit_length()}")

# --- Đoán ---
p.sendlineafter(b"guess): ", b"guess")
p.sendlineafter(b"What is n? ", str(n_final).encode())

p.interactive()