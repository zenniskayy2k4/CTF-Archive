# Try varying number of reverse layers from 90 to 110 to see if any yields a key that decrypts properly.
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes
from Crypto.Util.Padding import pad, unpad

p = 15471456606036645889
y0 = 3681934504574973317
y1 = 4155039551524372589
y2 = 9036939555423197298
iv = bytes.fromhex("6c9315b13f092fbc49adffbf1c770b54")
enc_flag = bytes.fromhex("af9dc7dfd04bdf4b61a1cf5ec6f9537819592e44b4a20c87455d01f67d738c035837915903330b67168ca91147299c422616390dae7be68212e37801b76a74d4")

def modInverse(n, m):
    """Tính nghịch đảo modular n^-1 mod m"""
    return pow(n, -1, m)

def find_lcg_params(s0, s1, s2, m):
    """Tìm tham số a, b của LCG từ 3 output liên tiếp"""
    a = ((s2 - s1) * modInverse(s1 - s0, m)) % m
    b = (s1 - a * s0) % m
    return a, b

def compute_r_for_layers(layers):
    a_100, b_100 = find_lcg_params(y0, y1, y2, p)
    x_100 = ((y0 - b_100) * modInverse(a_100, p)) % p
    params_as_outputs = [a_100, b_100, x_100]
    for i in range(layers, 0, -1):
        s0, s1, s2 = params_as_outputs
        prev_a, prev_b = find_lcg_params(s0, s1, s2, p)
        prev_x = ((s0 - prev_b) * modInverse(prev_a, p)) % p
        params_as_outputs = [prev_a, prev_b, prev_x]
    out1, out2, out3 = params_as_outputs
    a0, b0 = find_lcg_params(out1, out2, out3, p)
    r_val = (a0 * out3 + b0) % p
    return r_val, params_as_outputs

valid = []
for L in range(90, 111):
    try:
        r_cand, params = compute_r_for_layers(L)
    except Exception as e:
        print("Layer",L,"error:",e); continue
    # derive key as in original main.py
    key = pad(long_to_bytes(r_cand**2), 16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    dec = cipher.decrypt(enc_flag)
    try:
        plain = unpad(dec, 16)
    except Exception:
        plain = None
    if plain and b"LITCTF{" in plain:
        print("Found at layers", L)
        print("r=", r_cand)
        print("flag=", plain.decode())
        valid.append((L, r_cand, plain))
    # also check if plaintext contains 'LITCTF{' even without valid padding
    if (plain and b"LITCTF{" in plain) or (b"LITCTF{" in dec):
        print("Maybe found at L",L)
        print("r:", r_cand)
        print(dec[:200])
print("Done. Found", len(valid))
