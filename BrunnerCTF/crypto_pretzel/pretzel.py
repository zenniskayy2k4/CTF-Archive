# Making a pretzel is fairly simple in principle, but hard to master - unless you know how ;-)

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from public import p_list, a_list, G_list, looks_done
from secret import d, k, flag

assert flag[:8] + flag[-1] == "brunner{}"


# However basically it's just about the following:

# 1) The key to a good pretzel is the dough:
dough = b""

# 2) And the dough is shaped into specific curves of the general shape:
# y**2 %p = (x**3 +a*x +b) %p


def mul(k, P, p, a):
    R = None
    A = P
    while k:
        if k & 1:
            R = add(R, A, p, a)
        A = add(A, A, p, a)
        k >>= 1
    return R


def add(P, Q, p, a):
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and (y1 + y2) % p == 0:
        return None
    if P == Q:
        slope = (3 * x1 * x1 + a) * inv((2 * y1) % p, p) % p
    else:
        slope = (y2 - y1) * inv((x2 - x1) % p, p) % p
    x3 = (slope * slope - x1 - x2) % p
    y3 = (slope * (x1 - x3) - y1) % p
    return (x3, y3)


def inv(x, p):
    return pow(x, p - 2, p)


Q_list = [mul(d, G, p, a) for p, a, G in zip(p_list, a_list, G_list)]


# 3) And those shaped curves of dough are baked in the oven:
def bake(Q, p, a, G, k):
    R = mul(k, G, p, a)
    Sx = mul(k, Q, p, a)[0]
    return R, Sx


# 4) And look for the colour, to see when they are done:
colour = HKDF(
    algorithm=SHA256(),
    length=32,
    # Remember to sprinkle with salt, to make it a pretzel :)
    salt=b"pretzelsalt-sprinkle_for_the_win",
    info=b"pretzelbaking",
)

# And voila! Here's your pretzel: :)
with open("pretzel.csv", "w") as f:
    f.write("curve_index,Rx,Ry,Qx,Qy")
    for i, Q, p, a, G in zip(range(1, 3), Q_list, p_list, a_list, G_list):
        R, Sx = bake(Q, p, a, G, k)
        dough += Sx.to_bytes((Sx.bit_length() + 7) // 8, "big")
        f.write(f"\n{i},{R[0]},{R[1]},{Q[0]},{Q[1]}")

baked_just_right = (
    AESGCM(colour.derive(dough))
    .encrypt(b"pretzelnonce", flag[8:-1].encode(), None)
    .hex()
)
assert baked_just_right == looks_done
