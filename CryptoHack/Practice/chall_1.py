from Crypto.Util.number import *

e = 65537

p = getPrime(1024)
q1 = getPrime(1024)
q2 = getPrime(1024)

n1 = p * q1
n2 = p * q2

flag = b"CTF{gcd_1s_4w3s0m3_https://zenniskayy2k4.github.io/posts/csaw-ctf-qualification-round-2025/#obligatory-rsa}"
m = bytes_to_long(flag)

c1 = pow(m, e, n1)
c2 = pow(m, e, n2)

with open("output.txt", "w", encoding="utf-8") as f:
    f.write(f"e = {e}\n")
    f.write(f"n1 = {n1}\n")
    f.write(f"n2 = {n2}\n")
    f.write(f"d1 = {c1}\n")
    f.write(f"d2 = {c2}\n")