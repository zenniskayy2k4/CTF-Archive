from pwn import *
import math

# Hàm tính nghịch đảo modulo
def inverse(a, m):
    return pow(a, -1, m)

def solve():
    io = remote('y2k-but-real-fcd2f1c127c72448.instancer.batmans.kitchen', 1337, ssl=True)

    io.recvuntil(b"The last 8 access codes were:\n")
    data = io.recvline().decode().strip()
    # Chuyển string list [x, x, ...] thành list int
    x = eval(data)
    
    print(f"[*] Received sequence: {x}")

    # Bước 1: Tìm m
    y = []
    for i in range(len(x) - 1):
        y.append(x[i+1] - x[i])

    g = []
    for i in range(len(y) - 2):
        g.append(abs(y[i+2] * y[i] - y[i+1]**2))

    m = g[0]
    for val in g[1:]:
        m = math.gcd(m, val)
    
    # Do m là semiprime 32-bit, nếu gcd ra số quá lớn, 
    # ta có thể cần xử lý thêm, nhưng thường gcd này chính là m.
    print(f"[*] Recovered m: {m}")

    # Bước 2: Tìm a
    # a = y1 * inv(y0) mod m
    try:
        a = (y[1] * inverse(y[0], m)) % m
        print(f"[*] Recovered a: {a}")
    except ValueError:
        print("[!] Không tìm được nghịch đảo, có thể m cần được rút gọn hoặc y[0] chung ước với m.")
        return

    # Bước 3: Tìm c
    c = (x[1] - a * x[0]) % m
    print(f"[*] Recovered c: {c}")

    # Dự đoán 5 số tiếp theo
    curr = x[-1]
    predictions = []
    for _ in range(5):
        curr = (a * curr + c) % m
        predictions.append(str(curr))

    payload = ",".join(predictions)
    print(f"[*] Sending predictions: {payload}")
    
    io.sendlineafter(b"> ", payload.encode())
    print(io.recvall().decode())

if __name__ == "__main__":
    solve()