from pwn import *
from Crypto.Util.number import inverse
from sympy.ntheory import factorint
from sympy.ntheory.modular import crt
import re

# --- CẤU HÌNH ---
HOST = "curve.ctf.pascalctf.it"
PORT = 5004

# --- THÔNG SỐ CURVE (TỪ FILE ĐỀ BÀI) ---
p = 1844669347765474229
a = 0
b = 1
n = 1844669347765474230
Gx = 27
Gy = 728430165157041631

# --- CLASS POINT (TỪ FILE ĐỀ BÀI - ĐÃ TỐI ƯU CHO SOLVER) ---
class Point:
    def __init__(self, x, y):
        self.x = x
        self.y = y
    
    def __eq__(self, other):
        return self.x == other.x and self.y == other.y

    def __add__(self, other):
        if self.x is None: return other
        if other.x is None: return self
        if self.x == other.x and self.y == (-other.y % p):
            return Point(None, None)
        if self.x == other.x:
            s = (3 * self.x**2 + a) * inverse(2 * self.y, p) % p
        else:
            s = (other.y - self.y) * inverse(other.x - self.x, p) % p
        x3 = (s*s - self.x - other.x) % p
        y3 = (s * (self.x - x3) - self.y) % p
        return Point(x3, y3)
    
    def __rmul__(self, scalar):
        result = Point(None, None)
        addend = self
        while scalar:
            if scalar & 1:
                result = result + addend
            addend = addend + addend
            scalar >>= 1
        return result
    
    def __str__(self):
        return f"({self.x}, {self.y})"

# --- ATTACK (POHLIG-HELLMAN) ---
def solve_dlp_small_subgroup(generator, target, sub_order):
    """
    Giải bài toán Discrete Log trên nhóm con nhỏ bằng Brute Force.
    Tìm x sao cho: x * generator = target
    Trong đó, order của generator là sub_order (rất nhỏ).
    """
    # Vì sub_order < 100, ta dùng vòng lặp đơn giản thay vì BSGS
    current = Point(None, None) # Điểm vô cực (0 * G)
    for i in range(sub_order):
        if current == target:
            return i
        current = current + generator
    return None

def main():
    # 1. Kết nối và lấy tọa độ Q
    r = remote(HOST, PORT)
    
    r.recvuntil(b"Q = (")
    q_data = r.recvuntil(b")").decode().strip(')')
    qx, qy = map(int, q_data.split(', '))
    
    G = Point(Gx, Gy)
    Q = Point(qx, qy)
    
    print(f"[*] Target Point Q: {Q}")
    print(f"[*] Curve Order n: {n}")

    # 2. Phân tích thừa số nguyên tố n (Smooth Number)
    print("[*] Factoring n...")
    factors = factorint(n)
    print(f"[*] Factors of n: {factors}")
    
    remainders = []
    moduli = []

    # 3. Thuật toán Pohlig-Hellman
    print("[*] Performing Pohlig-Hellman attack...")
    
    for prime, exponent in factors.items():
        # Ở bài này, exponent đều là 1, nhưng ta viết code tổng quát
        modulus = prime ** exponent
        
        # Chuyển bài toán về nhóm con cấp modulus
        # cofactor = n // modulus
        cofactor = n // modulus
        
        # Tạo generator và target của nhóm con
        # G_sub = (n / p^k) * G
        # Q_sub = (n / p^k) * Q
        G_sub = cofactor * G
        Q_sub = cofactor * Q
        
        # Giải DLP nhỏ: d_sub = log(Q_sub, G_sub) mod modulus
        # Vì modulus tối đa là 53, hàm này chạy tức thì
        d_sub = solve_dlp_small_subgroup(G_sub, Q_sub, modulus)
        
        if d_sub is not None:
            remainders.append(d_sub)
            moduli.append(modulus)
            print(f"    [+] Log mod {modulus} = {d_sub}")
        else:
            print(f"    [-] Failed to solve for mod {modulus}")
            exit(1)

    # 4. Chinese Remainder Theorem (CRT) để tìm secret gốc
    print("[*] Reconstructing secret using CRT...")
    secret = crt(moduli, remainders)[0]
    print(f"[+] Found Secret: {secret}")
    print(f"[+] Verify: {secret} * G == Q ? {secret * G == Q}")

    # 5. Gửi secret lên server để lấy cờ
    r.sendline(b"1") # Chọn option 1: Guess secret
    r.recvuntil(b"secret (hex): ")
    r.sendline(hex(secret).encode()) # Gửi dưới dạng hex
    
    flag = r.recvall().decode()
    print("\n" + flag)

if __name__ == "__main__":
    main()