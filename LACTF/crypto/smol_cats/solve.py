import os
os.environ['TERM'] = 'linux'
os.environ['TERMINFO'] = '/usr/share/terminfo'

from pwn import *

# 1. Khởi tạo kết nối
io = remote('chall.lac.tf', 31225)

# 2. Xử lý Proof of Work (PoW) tự động
# Server yêu cầu chạy lệnh: curl -sSfL https://pwn.red/pow | sh -s ...
pow_command = io.recvline_contains(b"curl").decode().strip()
log.info(f"Đang giải PoW: {pow_command}")
pow_solution = subprocess.check_output(pow_command, shell=True).strip()
io.sendlineafter(b"solution:", pow_solution)

# 3. Thu thập dữ liệu n, e, c từ server
io.recvuntil(b"n = ")
n = int(io.recvline().strip())
io.recvuntil(b"e = ")
e = int(io.recvline().strip())
io.recvuntil(b"c = ")
c = int(io.recvline().strip())

log.success(f"Đã lấy được n: {n}")

# 4. Sử dụng SageMath để Factor và Decrypt
# Lưu ý: Khi chạy bằng 'sage -python', bạn có quyền truy cập vào các hàm của Sage
from sage.all import factor, IntegerModRing

log.info("Đang phân tích n thành nhân tử (với SageMath)...")
factors = factor(n)
p, q = [int(f[0]) for f in factors]
log.success(f"P: {p}\nQ: {q}")

# Tính toán trên vành số nguyên mod n
R = IntegerModRing(n)
m = R(c).nth_root(e)

# 5. Gửi kết quả
log.info(f"Kết quả m: {m}")
io.sendlineafter(b"How many treats do I want?", str(m).encode())

# Tương tác tiếp để lấy Flag
io.interactive()