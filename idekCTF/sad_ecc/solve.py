# solve.py
from pwn import *
import ast
from sage.all import *

# --- SageMath Code ---
# Chạy script này bằng lệnh: sage -python solve.py

# Địa chỉ server
HOST = "sad-ecc.chal.idek.team"
PORT = 1337

# Kết nối
r = remote(HOST, PORT)

# 1. Nhận n
r.recvuntil(b"n = ")
n_str = r.recvline().strip().decode()
n = int(n_str)
print(f"[+] n = {n}")

# 2. Nhận điểm mẫu để tính b
r.sendlineafter(b"> ", b"1")
r.recvuntil(b"Here is your point:\n")
point_str = r.recvline().strip().decode()
# Dùng ast.literal_eval để parse tuple an toàn
# Point str sẽ có dạng "DummyPoint(x, y)"
point_tuple = ast.literal_eval(point_str.replace("DummyPoint", ""))
Px, Py = point_tuple[0], point_tuple[1]
print(f"[+] Got sample point P = ({Px}, {Py})")

# 3. Tính hằng số b của đường cong
# x^2 = (y - 1337)^3 + b  (mod n)
# b = x^2 - (y - 1337)^3 (mod n)
c = 1337
b = (pow(Px, 2, n) - pow(Py - c, 3, n)) % n
print(f"[+] Calculated b = {b}")

# 4. Giải thử thách chính
r.sendlineafter(b"> ", b"2")
r.recvuntil(b"Sums (x+y): ")
sums_str = r.recvline().strip().decode()
sums = ast.literal_eval(sums_str)
print(f"[+] Received sums: {sums}")

# Chuẩn bị môi trường SageMath
F = GF(n)
R = PolynomialRing(F, 'y')
y = R.gen()

final_coords = []

for S in sums:
    print(f"[*] Solving for S = {S}")
    
    # Xây dựng đa thức bậc ba
    # y^3 + (-3c - 1)y^2 + (3c^2 + 2S)y + (b - S^2 - c^3) = 0
    c2 = -3 * c - 1
    c1 = 3 * c**2 + 2 * S
    c0 = b - S**2 - c**3
    
    poly = y**3 + c2*y**2 + c1*y + c0
    
    # Tìm nghiệm
    roots = poly.roots()
    
    # Giả định chỉ có 1 nghiệm duy nhất
    assert len(roots) == 1, "Expected one root, found multiple"
    y_sol = int(roots[0][0])
    
    # Tính x tương ứng
    x_sol = (S - y_sol) % n
    
    # Kiểm tra lại xem điểm có nằm trên đường cong không
    assert pow(x_sol, 2, n) == (pow(y_sol - c, 3, n) + b) % n
    
    print(f"    Found point: ({x_sol}, {y_sol})")
    final_coords.append((x_sol, y_sol))

# 5. Gửi kết quả
payload = str(final_coords)
print(f"[+] Sending payload: {payload}")
r.sendlineafter(b"Your reveal: ", payload.encode())

# 6. Nhận flag
result = r.recvall(timeout=5)
print(result.decode())