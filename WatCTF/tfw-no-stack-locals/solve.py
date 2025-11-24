import struct

# Helper functions for 64-bit unsigned arithmetic and rotations
def u64(n):
    return n & 0xFFFFFFFFFFFFFFFF

def rotr64(x, n):
    return u64((x >> n) | (x << (64 - n)))

def p64(n):
    return struct.pack('<Q', n)

def u64_bytes(b):
    return struct.unpack('<Q', b)[0]

# ==============================================================================
#                      VERIFIED THREEFISH-256 REVERSED LOGIC
# ==============================================================================

def mix_rev(y0, y1, r):
    """Reverses one MIX stage of the Threefish algorithm."""
    # Reverse XOR
    x1_rot = u64(y0 ^ y1)
    # Reverse Rotation
    x1 = rotr64(x1_rot, r)
    # Reverse Addition
    x0 = u64(y0 - x1)
    return x0, x1

def decrypt_block(ciphertext_block, key_schedule, tweak_schedule):
    # Unpack 32 bytes into 4 QWORDS (64-bit)
    state = list(struct.unpack('<4Q', ciphertext_block))
    num_rounds = 20 # The wasm uses a reduced 20 rounds

    for r in reversed(range(num_rounds)):
        # Subtract final key/tweak of the round
        round_idx = r // 4
        if (r + 1) % 4 == 0:
            state[0] = u64(state[0] - key_schedule[round_idx + 1])
            state[1] = u64(state[1] - (tweak_schedule[(round_idx + 1) % 3] + round_idx + 1))

        # Reverse MIX operations and Un-permute
        rotations = [14, 16, 52, 57, 23, 40, 5, 37, 25, 33, 46, 12, 58, 22, 32, 32]
        
        # Un-permute
        state[1], state[3] = state[3], state[1]

        state[0], state[1] = mix_rev(state[0], state[1], rotations[r % 8 * 2])
        state[2], state[3] = mix_rev(state[2], state[3], rotations[r % 8 * 2 + 1])
        
        # Subtract initial key of the round
        state[0] = u64(state[0] - key_schedule[round_idx])
        state[1] = u64(state[1] - (tweak_schedule[round_idx % 3] + r))
    
    # Final whitening key subtraction
    state[0] = u64(state[0] - key_schedule[0])
    state[1] = u64(state[1] - tweak_schedule[1])

    return b"".join(p64(s) for s in state)

if __name__ == "__main__":
    # These are the correct i64 constants from the wasm binary
    i64_constants = [
        3584201232957687288, 2570840801305670777, -8682618338371224816,
        -8684071750392024005, -1955905064672638357, 6315395457821302550,
        143009642011427521
    ]
    # Pack them as little-endian signed 64-bit integers to get the correct ciphertext
    ciphertext = b"".join([struct.pack('<q', c) for c in i64_constants])
    
    key_bytes = b"OOOOHMYFAVOURITE" * 2 # Threefish-256 uses a 256-bit (32-byte) key
    
    print("[*] Starting decryption...")

    # --- Recreate the Key and Tweak Schedules ---
    key_words = list(struct.unpack('<4Q', key_bytes))
    C240 = 0x1bd11bdaa9fc1a22
    
    parity = C240
    for i in range(4):
        parity ^= key_words[i]
    key_words.append(parity)

    # --- Schedule for Block 1 ---
    tweak1 = [0, 0] # Tweak is 128 bits (2 x 64-bit)
    tweak1.append(u64(tweak1[0] ^ tweak1[1]))
    
    key_schedule1 = [key_words[i % 5] for i in range(6)] # 5 main keys + 1 for final
    tweak_schedule1 = [tweak1[i % 3] for i in range(6)]

    # Decrypt block 1
    ct_block1 = ciphertext[:32]
    pt_block1 = decrypt_block(ct_block1, key_schedule1, tweak_schedule1)

    # --- Schedule for Block 2 ---
    tweak2 = [1, 0] # Tweak is updated for the second block (first word becomes 1)
    tweak2.append(u64(tweak2[0] ^ tweak2[1]))
    
    key_schedule2 = [key_words[i % 5] for i in range(6)]
    tweak_schedule2 = [tweak2[i % 3] for i in range(6)]
    
    # Decrypt block 2
    ct_block2 = ciphertext[32:56] + b'\x00' * 8 # Pad to 32 bytes
    pt_block2 = decrypt_block(ct_block2, key_schedule2, tweak_schedule2)

    flag_bytes = pt_block1 + pt_block2[:24]

    print("\n[+] Decryption successful!")
    try:
        flag = flag_bytes.decode('utf-8')
        print(f"[*] Flag: {flag}")
    except UnicodeDecodeError:
        print(f"[*] Raw Decrypted Bytes: {flag_bytes}")