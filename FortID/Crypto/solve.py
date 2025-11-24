from Crypto.PublicKey import RSA
from Crypto.Util.number import long_to_bytes, inverse, GCD

with open('key1.pub', 'r') as f:
    key1 = RSA.import_key(f.read())
with open('key2.pub', 'r') as f:
    key2 = RSA.import_key(f.read())

n1, e1 = key1.n, key1.e
n2, e2 = key2.n, key2.e

print("n1 =", n1)
print("e1 =", e1)
print("n2 =", n2)
print("e2 =", e2)

c1 = int(open('flag1.enc').read().strip(), 16)
c2 = int(open('flag2.enc').read().strip(), 16)

# 1. Tìm prime chung
p = GCD(n1, n2)
if p == 1:
    print("Không có prime chung, không giải được bằng phương pháp này.")
    exit()

q1 = n1 // p
q2 = n2 // p

# 2. Tính private key
phi1 = (p - 1) * (q1 - 1)
phi2 = (p - 1) * (q2 - 1)
d1 = inverse(e1, phi1)
d2 = inverse(e2, phi2)

# 3. Giải mã
m1 = pow(c1, d1, n1)
m2 = pow(c2, d2, n2)

# 4. XOR hai số nguyên đã giải mã
m_final = m1 ^ m2
final_flag_bytes = long_to_bytes(m_final)

print(long_to_bytes(m1))
print(long_to_bytes(m2))