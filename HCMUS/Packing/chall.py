from sage.all import *
import random
from Crypto.Util.number import getPrime, bytes_to_long

MOD = 3 

def genKeys(n):
    b = []
    s = 1000

    for i in range(n):
        b.append(random.randint((MOD-1)*s + 1, MOD*MOD*s))
        s += b[-1]
    
    s = random.randint((MOD-1)*s + 1, MOD*MOD*s)
    
    m = getPrime((s + 1).bit_length() + 1)
    u = random.randint(2, m)
    a = [x*u % m for x in b]
    return (a, m), u

def encrypt(pub, message):
    a, m = pub
    ct = 0
        
    for i in range(len(message)):
        ct = (ct + message[i]*a[i]) % m

    return ct

def getDigits(n):
    d = []
    while n > 0:
        d.append(n % MOD)
        n //= MOD
    return d[::-1]

def toInt(d):
    res = 0 
    for x in d:
        res = (res*MOD + x)
    return res

flag = b"warmup{redacted}"
digits = getDigits(bytes_to_long(flag))
pub, prv = genKeys(len(digits))

ct = encrypt(pub, digits)

print(f"{pub = }")
print(f"{ct = }")