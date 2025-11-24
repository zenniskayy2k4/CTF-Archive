from Crypto.Util.number import isPrime, getPrime, bytes_to_long
from math import gcd
from random import randint

FLAG = b"0160ca14{77613813229115705407983120551706296959236412766954020268752564135993144645418}"

def find_small_divisor(number: int):
    divisor = 10
    while(number%divisor != 0):
        divisor += 1

    return divisor

p = getPrime(16)
q = getPrime(16)
assert p != q

r = getPrime(256)

a = bytes_to_long(FLAG)

k = randint(1, r-1)

x = a**p-k**p
y = a**q-k**q

d = find_small_divisor(gcd(x+y, x))
number = (k*gcd((x+y)//d, y//d)) % r

print(f"p = {p}")
print(f"q = {q}")
print(f"r = {r}")
print(f"k = {k}")
print(f"d = {d}")
print(f"number = {number}")
