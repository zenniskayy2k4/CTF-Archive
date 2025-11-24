from Crypto.Util.number import getPrime, bytes_to_long
import sys

e = 3

flag = b"CTF{n33d_a_lArg3r_e_d0cd6eae}"

m = bytes_to_long(flag)

# Tìm n = p*q sao cho m^e < n
while True:
    p = getPrime(512)
    q = getPrime(512)
    n = p * q
    if m**e < n:
        break

c = pow(m, e, n)

with open("chall2.txt", "w", encoding="utf-8") as f:
    f.write(f"e = {e}\n")
    f.write(f"n = {n}\n")
    f.write(f"c = {c}\n")
