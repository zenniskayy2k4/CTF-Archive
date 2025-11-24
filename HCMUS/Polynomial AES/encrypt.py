from Crypto.Util.number import getPrime, getRandomRange, getRandomInteger
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

flag = open("flag.txt", "rb").read()


def sha256(s: bytes) -> bytes:
    h = SHA256.new()
    h.update(s)
    return h.digest()


def generate_key() -> bytes:
    d = getRandomRange(20, 30)
    p = getPrime(1024)
    q = []
    for _ in range(d + 1):
        q.append(getRandomInteger(100))

    def eval(x: int) -> int:
        ans = 0
        mul = 1
        for i in range(d + 1):
            ans = (ans + mul * q[i]) % p
            mul = (mul * x) % p
        return ans

    print(f"p = {p}")
    print(f"q = {q}")

    H = range(1, p)
    s = 0
    for h in H:
        s = (s + eval(h)) % p

    key = sha256(str(s).encode())
    return key


key = generate_key()
cipher = AES.new(key, mode=AES.MODE_ECB)
ct = cipher.encrypt(pad(flag, AES.block_size))

print(f"Encrypted flag: {ct.hex()}")
