#!/usr/local/bin/python3
from Crypto.Util.number import long_to_bytes, getPrime
from secret import flag

ps = []
N = 1
for _ in range(6*7):
    ps.append(getPrime(6+7+6+7))
    N *= ps[-1]

print(' '.join(str(p) for p in ps))
n = int(input('Your integer?'))
goods = []
# Bharmeesh: hello!
goods.append(6)
goods.append(7)
goods.append(6 - 7)
goods.append(6 + 7)
if 0 <= n < N and all(0 in [(n - good) % p for good in goods] for p in ps):
    print(eval(long_to_bytes(n)))