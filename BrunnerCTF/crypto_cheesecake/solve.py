# solve_debug_full.py
# Put in same folder as recipe.py, run with python
from pathlib import Path
import recipe
from Crypto.Cipher import AES, ARC4
from Crypto.PublicKey import RSA
from random import Random
import binascii, base64, zlib, bz2, gzip, re

def inv_beat_INTEGERgredients(out_bytes, int_key):
    s = """,&6y5jz*r~6BR `|FQ39*So7w`,&oC*1^PZhCKp}UT. C^tgoVBRb$z`*Zpa)XB>|b^%MO~6~IR_whvM!}|mA |@jj090!*gP;?Qf*Cj0$\"{@5&[HjpVTnig|>?]Q$CT4}{S3i8iC[kUq2GfW3\\>iu:O30qp"""
    d = [chr(i) for i in range(32,127)]
    def s2i(s):
        return sum(d.index(c)*len(d)**i for i,c in enumerate(s[::-1]))
    i = s2i(s)//int_key
    n_out = int.from_bytes(out_bytes, 'big')
    n_in = n_out + i
    in_bytes = n_in.to_bytes((n_in.bit_length() + 7) // 8, 'big')
    return in_bytes

def inv_cAESugar(out_bytes, key_byte):
    from Crypto.Cipher import AES
    key = bytes([key_byte] * 16)
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(out_bytes)

def inv_vanilla_eXORtract(out_bytes, seed_val):
    sr = Random(seed_val+1)
    key = bytes(sr.getrandbits(8) for _ in range(len(out_bytes)))
    return bytes(b ^ k for b,k in zip(out_bytes, key))

def inv_sour_STREAM(out_bytes, key_byte):
    from Crypto.Cipher import ARC4
    cipher = ARC4.new(bytes([key_byte]))
    return cipher.encrypt(out_bytes)

def inv_an_egGOST(out_bytes, int_key):
    # use recipe.an_egGOST to ensure identical IV/behavior to challenge
    return recipe.an_egGOST(out_bytes, int_key)

def inv_ground_CAESARdamom(out_bytes, key):
    return bytes((b - key) % 256 for b in out_bytes)

def inv_melted_BITter(out_bytes, shift):
    s = shift % 8
    return bytes(((b >> s) | ((b << (8 - s)) & 0xFF)) & 0xFF for b in out_bytes)

def inv_ADDed_SOLUTION_giving_bREADMETEXTure(out_bytes, e):
    tmp = bytes(b ^ e for b in out_bytes)
    A = tmp[:64]; B = tmp[64:]
    c = 46412520328440256871399753615737168429362885041489783567894921161800073479497
    d = 30147310566698376871947829873776459834598978229983782629303180618977163687145
    in_first = recipe.SPECIAL_technique(A, c, d)
    in_last = recipe.SPECIAL_technique(B, c, d)
    return in_first + in_last

def inv_graham_crackeRSA(out_bytes, seed_val):
    # reconstruct RSA key exactly as recipe's graham_crackeRSA did
    prng = Random(seed_val)
    def randfunc(n): return prng.getrandbits(n * 8).to_bytes(n, 'big')
    key = RSA.generate(1024, randfunc=randfunc)
    c_int = int.from_bytes(out_bytes, 'big')
    m_int = pow(c_int, key.d, key.n)
    plain = m_int.to_bytes((m_int.bit_length() + 7) // 8, 'big')
    return plain

# order (inverse sequence)
steps = [
    (recipe.beat_INTEGERgredients, inv_beat_INTEGERgredients),
    (recipe.cAESugar, inv_cAESugar),
    (recipe.vanilla_eXORtract, inv_vanilla_eXORtract),
    (recipe.sour_STREAM, inv_sour_STREAM),
    (recipe.an_egGOST, inv_an_egGOST),
    (recipe.ground_CAESARdamom, inv_ground_CAESARdamom),
    (recipe.melted_BITter, inv_melted_BITter),
    (recipe.ADDed_SOLUTION_giving_bREADMETEXTure, inv_ADDed_SOLUTION_giving_bREADMETEXTure),
    (recipe.graham_crackeRSA, inv_graham_crackeRSA),
]

state = b''  # final mix is empty
for funcobj, inv in steps:
    s = recipe.ranDOCm(funcobj)
    print(f"Inverting {funcobj.__name__} with seed/key {s} ... (state len {len(state)})")
    state = inv(state, s)
    print(" -> len", len(state), " hex pref:", state.hex()[:64])
    print()

final = state
print("=== Final bytes hex ===")
print(final.hex())
print("len:", len(final))
print()

# Try many decodings / transforms
def try_printings(b):
    print("--- try raw decodings ---")
    try:
        print("utf-8:", b.decode('utf-8'))
    except Exception as e:
        print("utf-8 fail:", e)
    print("utf-8 replace:", b.decode('utf-8', errors='replace'))
    print("latin-1:", b.decode('latin-1', errors='replace'))
    print("ascii ignore:", b.decode('ascii', errors='ignore'))
    print()

def find_substrings(b):
    txts = [
        b.decode('latin-1', errors='ignore'),
        b.decode('utf-8', errors='ignore'),
        binascii.hexlify(b).decode(),
        base64.b64encode(b).decode(),
    ]
    for t in txts:
        if 'brunner{' in t:
            print("Found 'brunner{' in:", t)
            return True
    return False

try_printings(final)
if find_substrings(final):
    print("Found brunner in one of variants! stop.")
else:
    print("No direct 'brunner{' found. Trying heuristic transforms...")

# 1) strip leading/trailing nulls and try again
s1 = final.strip(b'\x00')
print("After strip NUL len", len(s1))
try_printings(s1)
if find_substrings(s1):
    print("Found after strip NUL"); raise SystemExit

# 2) if final is ascii hex (only hex chars), try interpreting as hex
ascii_try = final.decode('ascii', errors='ignore')
hex_candidate = re.sub(r'[^0-9a-fA-F]', '', ascii_try)
if len(hex_candidate) > 0 and len(hex_candidate) % 2 == 0:
    print("Candidate ascii-hex (cleaned). Trying to decode and pass to get_FLAG_from_HEX...")
    try:
        decoded = binascii.unhexlify(hex_candidate)
        print("decoded bytes len", len(decoded))
        try_printings(decoded)
        # maybe recipe expects hex string, try both
        try:
            flag = recipe.get_FLAG_from_HEX(hex_candidate)
            print("get_FLAG_from_HEX result:", flag)
        except Exception as e:
            print("get_FLAG_from_HEX failed:", e)
    except Exception as e:
        print("hex unhexlify failed:", e)

# 3) try decompression
print("\nTrying decompress attempts...")
for name, fn in [('zlib', zlib.decompress), ('bz2', bz2.decompress), ('gzip', lambda x: gzip.decompress(x))]:
    try:
        out = fn(final)
        print(f"{name} decompress OK, len {len(out)}")
        try_printings(out)
        if 'brunner{' in out.decode('latin-1', errors='ignore'):
            print("FOUND via decompress", name, out.decode('latin-1', errors='ignore'))
    except Exception as e:
        print(f"{name} failed: {e}")

# 4) try base64 decode of printable variants
print("\nTrying base64 guesses from ascii-ish decodings...")
for cand in [final, final.strip(b'\x00'), final.hex().encode(), binascii.hexlify(final)]:
    try:
        b64 = base64.b64decode(cand, validate=False)
        print("base64 decode len:", len(b64))
        try_printings(b64)
    except Exception as e:
        print("base64 decode failed for candidate:", e)

print("\nFinished trials. If nothing found, paste this whole output to the challenge thread and I'll analyze next.")
