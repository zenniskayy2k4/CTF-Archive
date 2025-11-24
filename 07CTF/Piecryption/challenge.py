import random
from secret import FLAG

N = 10**8
assert len(FLAG) == 38
digits = open('pi-100m.txt').read().strip()[2:]
offset= random.randint(0,N)
encoded = str(int.from_bytes(FLAG))
ciphertext = []
for e in encoded: 
    for i in range(offset,N):
        if digits[i] == str(e):
            ciphertext.append(i-offset)
            offset = i
            break
    else:
        raise Exception("UnSufficient Digits!")
print("ciphertext = ",ciphertext)
