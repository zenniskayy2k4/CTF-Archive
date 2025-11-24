from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Curve parameters from public.py
p1 = 90914882565236544063038156198227615150419011397631849109118664164237971030017
a1 = 90914882565236544063038156198227615150419011397631849109118664164237971030014
p2 = 101770390931239908848572362293957064456886252931837205053316532709789112729601
a2 = 101770390931239908848572362293957064456886252931837205053316532709789112729598

# Points G and Q from public.py
G1 = (31050621188682335241371326692276113333037865262574375461832507815231354661108, 55368851359349074519270007940435891631334772844860139655892860934285057401271)
Q1 = (60654019012410067120711398073857680949024612696301415588044550720435874093539, 5711354888055925579531317396109415258913923078804516891939253983176376703093)
G2 = (42588099604299172563555389284269876930484458686346414575256244246451517913988, 92018355397681073752377324460550882831430130854004599311301976509793681162305)
Q2 = (13490265511955479900549284118686344238389809927403063617313888747745925711037, 19074107476762576179530157100344097616389787965952709579366771786698037814080)

# Points R from pretzel.csv
R1 = (48754097786264306478841611668923047433814887971195884029152321559401093654195, 49206168873274225500422511678919192231279165324618551605443303894928093867399)
R2 = (21889169369905888234537833841072353198273271335611634161741428015496146337078, 36611417671603375551776660371980299772345552515075689971428640982420748083357)

# Function to compute inverse
def inv(x, p):
    return pow(x, p-2, p)

# Compute d using Smart attack with minus sign
def compute_d(xG, yG, xQ, yQ, p):
    minus_xG = (p - xG) % p
    minus_xQ = (p - xQ) % p
    inv_yG = inv(yG, p)
    phi_G = (minus_xG * inv_yG) % p
    inv_yQ = inv(yQ, p)
    phi_Q = (minus_xQ * inv_yQ) % p
    inv_phi_G = inv(phi_G, p)
    d = (phi_Q * inv_phi_G) % p
    return d

d1 = compute_d(G1[0], G1[1], Q1[0], Q1[1], p1)
d2 = compute_d(G2[0], G2[1], Q2[0], Q2[1], p2)

# Functions for elliptic curve operations from pretzel.py
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

def mul(k, P, p, a):
    R = None
    A = P
    while k:
        if k & 1:
            R = add(R, A, p, a)
        A = add(A, A, p, a)
        k >>= 1
    return R

# Compute Sx1 and Sx2
Sx1 = mul(d1, R1, p1, a1)[0]
Sx2 = mul(d2, R2, p2, a2)[0]

# Create dough with 32 bytes for each Sx
dough = Sx1.to_bytes(32, "big") + Sx2.to_bytes(32, "big")

# Derive key
salt = b"pretzelsalt-sprinkle_for_the_win"
info = b"pretzelbaking"
colour = HKDF(
    algorithm=SHA256(),
    length=32,
    salt=salt,
    info=info,
)
key = colour.derive(dough)

# Decrypt flag
nonce = b"pretzelnonce"
looks_done = "19ff2f6db79661f85f3befc726076fa62ddeee81a92b46545d620ca442a33f8292820fc40a9bf9d63935e9c6e5e50c70e9ce790b8126b8c9332cbff576a0b8d549209410e740d6a3e5a273d9689d3637c56e49aea22c0b101c3c593a2f53e21481bac83bc96e47e5852054128ca96c4d289392df56e5f3df327689ac5822a2a7f108"
encrypted = bytes.fromhex(looks_done)
aesgcm = AESGCM(key)
flag_part = aesgcm.decrypt(nonce, encrypted, None)
flag = "brunner{" + flag_part.decode() + "}"

print(flag)