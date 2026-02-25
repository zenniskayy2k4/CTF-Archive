import hashlib
from Crypto.Util.number import bytes_to_long, long_to_bytes, inverse

# Thông số đường cong secp256k1
n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141

# Message 1
msg1 = b'Beware the Krampus Syndicate!'
r1 = 0xa4312e31e6803220d694d1040391e8b7cc25a9b2592245fb586ce90a2b010b63
s1 = 0xe54321716f79543591ab4c67e989af3af301e62b3b70354b04e429d57f85aa2e

# Message 2 (Kế tiếp, nên k2 = k1 + 1)
msg2 = b'Santa is watching...'
r2 = 0x6c5f7047d21df064b3294de7d117dd1f7ccf5af872d053f12bddd4c6eb9f6192
s2 = 0x1ccf403d4a520bc3822c300516da8b29be93423ab544fb8dbff24ca0e1368367

# Tính Hash (z)
def get_z(msg):
    h = hashlib.sha256(msg).digest()
    return bytes_to_long(h)

z1 = get_z(msg1)
z2 = get_z(msg2)

# Tính toán khóa bí mật d
# Công thức: d = (1 - s2^-1 * z2 + s1^-1 * z1) / (s2^-1 * r2 - s1^-1 * r1) mod n

s1_inv = inverse(s1, n)
s2_inv = inverse(s2, n)

# Tử số (Numerator)
numerator = (1 - (s2_inv * z2) + (s1_inv * z1)) % n

# Mẫu số (Denominator)
denominator = ((s2_inv * r2) - (s1_inv * r1)) % n

# Private Key d
d = (numerator * inverse(denominator, n)) % n

real_d = d - 1

print(f"Recovered d (adjusted): {real_d}")
try:
    flag = long_to_bytes(real_d)
    print("Flag:", flag.decode())
except:
    print("Could not decode flag, raw bytes:", long_to_bytes(real_d))