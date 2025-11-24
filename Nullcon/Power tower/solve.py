# -*- coding: utf-8 -*-
# Power tower – full solver
#
# Ý tưởng: tính int_final % n bằng đệ quy mô-đun qua Carmichael λ(m),
# cùng tiêu chí "exponent lớn" (thêm +λ(m)) để xử lý trường hợp không đồng nguyên tố.
# Sau đó ghép key và giải AES-ECB để lấy flag.

from Crypto.Cipher import AES
from Crypto.Util import number
import math
import random
from binascii import unhexlify

n = 107502945843251244337535082460697583639357473016005252008262865481138355040617  # :contentReference[oaicite:2]{index=2}

# primes < 100 như trong chall.py: [p for p in range(100) if number.isPrime(p)]  [chall.py]
PRIMES = [p for p in range(100) if number.isPrime(p)]  # :contentReference[oaicite:3]{index=3}

# ====== Pollard Rho + Miller-Rabin để factor nhanh ======
def is_probable_prime(n, k=10):
    if n < 2:
        return False
    small = [2,3,5,7,11,13,17,19,23,29]
    for p in small:
        if n % p == 0:
            return n == p
    # Miller-Rabin
    d = n - 1
    s = 0
    while d % 2 == 0:
        s += 1
        d //= 2
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for __ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def pollards_rho(n):
    if n % 2 == 0:
        return 2
    if n % 3 == 0:
        return 3
    while True:
        x = random.randrange(2, n - 1)
        y = x
        c = random.randrange(1, n - 1)
        d = 1
        f = lambda v: (pow(v, 2, n) + c) % n
        while d == 1:
            x = f(x)
            y = f(f(y))
            d = math.gcd(abs(x - y), n)
        if d != n:
            return d

def factor(n, out=None):
    if out is None:
        out = []
    if n == 1:
        return out
    if is_probable_prime(n):
        out.append(n)
    else:
        d = pollards_rho(n)
        factor(d, out)
        factor(n // d, out)
    return out

def factorint(n):
    fac = {}
    for p in factor(n, []):
        fac[p] = fac.get(p, 0) + 1
    return fac

# ====== Hàm Carmichael λ(n) từ phân tích thừa số ======
def carmichael_from_factorization(fac):
    # λ(p^e) = phi(p^e) với p odd; với 2^e: e=1 ->1, e=2 ->2, e>=3 -> 2^(e-2)
    L = 1
    for p, e in fac.items():
        if p == 2 and e >= 3:
            v = 2 ** (e - 2)
        else:
            v = (p - 1) * (p ** (e - 1))
        L = math.lcm(L, v)
    return L

def carmichael(n):
    if n == 1:
        return 1
    return carmichael_from_factorization(factorint(n))

# ====== Kiểm tra "exponent đủ lớn" qua ngưỡng log ======
def ceil_log_base(T, a):
    """Nhỏ nhất x sao cho a^x >= T (T, a >= 1)"""
    if T <= 1:
        return 0
    x, cur = 0, 1
    while cur < T:
        cur *= a
        x += 1
        if x > 10000:
            break
    return x

from functools import lru_cache

@lru_cache(maxsize=None)
def is_large(level, T):
    """Trả về True nếu int_level >= T, với:
       int_0 = 1; int_{i+1} = PRIMES[i] ** int_i
    """
    if T <= 1:
        return True
    if level == 0:
        return 1 >= T
    a = PRIMES[level - 1]
    th = ceil_log_base(T, a)
    return is_large(level - 1, th)

@lru_cache(maxsize=None)
def tower_mod(level, m):
    """F(level) mod m, với F(0)=1, F(i+1)=PRIMES[i] ** F(i)"""
    if m == 1:
        return 0
    if level == 0:
        return 1 % m
    lam_m = carmichael(m)
    e_mod = tower_mod(level - 1, lam_m)
    # nếu exponent đủ lớn (>= λ(m)) thì cộng thêm λ(m)
    exp = e_mod + (lam_m if is_large(level - 1, lam_m) else 0)
    a = PRIMES[level - 1]
    return pow(a, exp, m)

# ====== Tính key và giải AES-ECB ======
def solve():
    # đọc ciphertext từ file như đề cung cấp [cipher.txt]
    with open('cipher.txt', 'r') as f:  # :contentReference[oaicite:4]{index=4}
        cipher_hex = f.read().strip()
    ct = unhexlify(cipher_hex)

    # int_final % n (32 bytes big-endian) [chall.py]
    int_mod_n = tower_mod(len(PRIMES), n)
    key = int_mod_n.to_bytes(32, 'big')  # :contentReference[oaicite:5]{index=5}

    aes = AES.new(key, AES.MODE_ECB)
    pt = aes.decrypt(ct)

    # chall padding bằng '_' (không phải PKCS#7) [chall.py]
    # In cả 2 dạng: giữ nguyên và rstrip('_')
    print("Plain (raw):", pt.decode('utf-8', errors='replace'))
    print("Plain (rstrip('_')):", pt.decode('utf-8', errors='replace').rstrip('_'))

if __name__ == "__main__":
    solve()