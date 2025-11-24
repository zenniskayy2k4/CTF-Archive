import base64
import hashlib
from itertools import cycle

def xor_cipher(data: bytes, key: bytes) -> bytes:
    """Performs a repeating-key XOR operation. It's its own inverse."""
    return bytes([x ^ y for x, y in zip(data, cycle(key))])

def reverse_byte_transform(data: bytes) -> bytes:
    """
    Reverses the (c * 7) % 256 operation.
    The modular multiplicative inverse of 7 mod 256 is 183.
    (7 * 183) % 256 = 1281 % 256 = 1.
    So, the inverse operation is (c * 183) % 256.
    """
    inv = pow(7, -1, 256) # This is 183
    return bytes([(byte * inv) % 256 for byte in data])

def generate_xor_key() -> bytes:
    """Generates the exact same XOR key used in the original script."""
    initial_key = b"skibidi"
    # The key is derived from sha256("skibidi" + "skibidi")
    # and truncated to the length of the initial key (7 bytes).
    key_material = initial_key + initial_key
    hashed_material = hashlib.sha256(key_material).digest()
    xor_key = hashed_material[:len(initial_key)]
    return xor_key

# The encoded flag from output.txt
encoded_flag = b"qjuA_QZVI_ua24NQ}fM1hX4ecdyVShKb2vJjeQJ@Jz=zws0^9Enr1fR+Em_5w2j=p4)2<#m3EZ?m3Oo@"

# --- REVERSAL STEPS ---

# Step 1: Reverse the Base85 encoding
print("[+] Reversing Base85 encoding...")
step4_data = base64.b85decode(encoded_flag)

# Step 2: Reverse the data reversal (by reversing it again)
print("[+] Reversing the data order...")
step3_data = step4_data[::-1]

# Step 3: Reverse the byte transformation
print("[+] Reversing the byte transformation `(c * 7) % 256`...")
step2_data = reverse_byte_transform(step3_data)

# Step 4: Generate the key and reverse the XOR cipher
print("[+] Generating the XOR key...")
xor_key = generate_xor_key()
print(f"    -> XOR Key: {xor_key.hex()}")

print("[+] Reversing the XOR cipher...")
original_flag_bytes = xor_cipher(step2_data, xor_key)

# Step 5: Decode the final bytes to get the flag string
flag = original_flag_bytes.decode()

print("\n" + "="*40)
print(f"SUCCESS! The decoded flag is:\n{flag}")
print("="*40)