import secrets
from secret import FLAG

alphabet = "bcdefghijklmnopqrstuvwxyz"

def random_key(m):
    key_len = secrets.randbelow(len(m) ** 2)
    if key_len < len(m):
        key_len = key_len + len(m)
    key = "".join(secrets.choice(alphabet) for i in range(key_len))
    return key

def encrypt(m):
    key = random_key(m)[0 : len(m)]
    ct = []
    for i in range(len(m)):
        x = (ord(m[i]) + ord(key[i])) % 26
        x += ord("a")
        ct.append(chr(x))
    return "".join(ct)

if __name__ == "__main__":
    a = FLAG[:6]
    b = FLAG[-1]
    pt = FLAG[6:-1]
    for i in range(0, 113):
        print(a, encrypt(pt), b, sep="")