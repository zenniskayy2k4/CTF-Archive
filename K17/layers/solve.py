from pwn import *
from Crypto.Util.number import long_to_bytes, bytes_to_long

# Helper function for XORing byte strings
def xor(a, b):
    return bytes([x ^ y for x, y in zip(a, b)])

# Connect to the server
conn = remote("challenge.secso.cc", 7004)

# Receive initial data
conn.recvuntil(b"n = ")
n = int(conn.recvline().strip())
conn.recvuntil(b"e = ")
e = int(conn.recvline().strip())
conn.recvuntil(b"challenge: ")
r_flag, c_flag, s_flag = eval(conn.recvline().strip())

log.info(f"n = {n}")
log.info(f"e = {e}")
log.info(f"r_flag = {r_flag}")
log.info(f"c_flag = {c_flag}")
log.info(f"s_flag = {s_flag}")

# --- Step 1: Recover the original AES ciphertext ---
log.info("Recovering original AES ciphertext...")
s_pow_e = pow(s_flag, e, n)
aes_c_flag_int = (s_pow_e * r_flag) % n
aes_c_flag_bytes = long_to_bytes(aes_c_flag_int)

# Ensure the byte string has a length that is a multiple of 16
# The original aes_c might be smaller than n, so long_to_bytes might produce a shorter string
# We need to pad it to the correct block alignment. The original flag is likely padded to 3 or 4 blocks.
# 64 bytes (4 blocks) is a safe assumption.
if len(aes_c_flag_bytes) % 16 != 0:
    padding_needed = 16 - (len(aes_c_flag_bytes) % 16)
    aes_c_flag_bytes = b'\x00' * padding_needed + aes_c_flag_bytes

log.success(f"Original AES ciphertext (hex): {aes_c_flag_bytes.hex()}")

assert len(aes_c_flag_bytes) % 16 == 0
blocks = [aes_c_flag_bytes[i:i+16] for i in range(0, len(aes_c_flag_bytes), 16)]
num_blocks = len(blocks)
log.info(f"Ciphertext consists of {num_blocks} blocks (IV + {num_blocks-1} data blocks).")

# --- Step 2: Padding Oracle Attack ---
plaintext = b""

for i in range(num_blocks - 1, 0, -1):
    log.info(f"Attacking block {i}...")
    
    c_target = blocks[i]
    c_prev = blocks[i-1]
    
    intermediate_block = b''
    crafted_prev_block = bytearray(16)

    for j in range(15, -1, -1):
        padding_val = 16 - j
        
        for k in range(len(intermediate_block)):
            crafted_prev_block[j + 1 + k] = intermediate_block[k] ^ padding_val

        for g in range(256):
            crafted_prev_block[j] = g
            
            # --- THE FIX IS HERE ---
            # Prepend a dummy block to ensure the total length is preserved
            # after bytes_to_long -> long_to_bytes conversion on the server.
            # Dummy IV (16 bytes) || Crafted Block (16 bytes) || Target Block (16 bytes)
            dummy_iv = b'\x01' * 16 
            payload_bytes = dummy_iv + bytes(crafted_prev_block) + c_target
            r_to_send = bytes_to_long(payload_bytes)
            
            conn.sendlineafter(b"hold? ", f"{r_to_send},1,1".encode())
            response = conn.recvline()
            
            if b"what is bro doing" not in response:
                intermediate_byte = g ^ padding_val
                intermediate_block = bytes([intermediate_byte]) + intermediate_block
                log.info(f"Found byte {15-j}/16: {hex(intermediate_byte)}")
                break
        else:
            log.error("Failed to find byte. Something is wrong.")
            conn.close()
            exit()

    p_block = xor(intermediate_block, c_prev)
    plaintext = p_block + plaintext
    log.success(f"Decrypted block {i}: {p_block}")

# --- Step 3: Unpad and print the flag ---
log.info(f"Full decrypted plaintext (with padding): {plaintext}")

# PKCS7 unpadding
pad_len = plaintext[-1]
flag = plaintext[:-pad_len]

log.success(f"FLAG: {flag.decode()}")

conn.close()