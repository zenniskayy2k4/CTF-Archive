from Crypto.Util.number import getPrime
import random
FLAG = b'07CTF{000000000100000001000000010000001}'

bits = 512
class LCG:
    def __init__(self, bits):
        self.p = getPrime(bits+1)
        self.b = self._gen()
        self.seed = self._gen()
        self.m = self._gen()

    def _gen(self):
        val = random.getrandbits(bits)        
        return val

    def next(self):
        self.seed = (self.m * self.seed + self.b) % self.p
        self.m = self._gen()
        return self.seed


lcg = LCG(bits)
chunks = [FLAG[i : i + 8] for i in range(0, len(FLAG), 8)]
chunks = [int.from_bytes(chunk,"big") for chunk in chunks]
enc = []
for chunk in chunks:
    next = lcg.next()
    enc.append(next ^ chunk)

hint = []
for _ in range(64):
    next = lcg.next()
    hint.append(next)

print(f"b = {lcg.b}")
print(f"p = {lcg.p}")
print(f"enc = {enc}")
print(f"hint = {hint}")
