# Encrypted data taken from offset 1239:0146 (36 bytes)
encrypted = [
    0xb6, 0x8c, 0x95, 0x8f, 0x9b, 0x85, 0x4c, 0x5e, 0xec, 0xb6, 0xb8, 0xc0, 
    0x97, 0x93, 0x0b, 0x58, 0x77, 0x50, 0xb0, 0x2c, 0x7e, 0x28, 0x7a, 0xf1, 
    0xb6, 0x04, 0xef, 0xbe, 0x5c, 0x44, 0x78, 0xe8, 0x99, 0x81, 0x04, 0x8f
]

# Seed data taken from offset 1239:016a (the next 36 bytes)
# The program uses this memory region as the continuation of the encrypted data
seed_part = [
    0x03, 0x40, 0xa7, 0x3f, 0xfa, 0xb7, 0x08, 0x01, 0x63, 0x52, 0xe3, 0xad, 
    0xd1, 0x85, 0x9f, 0x94, 0x21, 0xd5, 0x2a, 0x5c, 0x20, 0xd4, 0x31, 0x12, 
    0xce, 0xaa, 0x16, 0xc7, 0xad, 0xdf, 0x29, 0x5d, 0x72, 0xfc, 0x24, 0x90
]

# Final byte at 1239:018e
last_byte = [0x2c]

# Concatenate the entire encrypted sequence (73 bytes)
target = encrypted + seed_part + last_byte

def fun_tick(in_AX, extraout_DX):
    """
    Simulate function FUN_1000_007b (PRNG state update).
    in_AX: 16-bit Low state (original)
    extraout_DX: 4-bit High state (original)
    Returns (new_low, new_high) as 16-bit values.
    """
    iVar3 = 3
    uVar2 = in_AX
    uVar4 = extraout_DX
    
    # Run a 3-step shift loop (effectively shifting the combined state right by 3)
    while iVar3 > 0:
        uVar1 = uVar4 & 1
        uVar4 = (uVar4 >> 1) & 0xFFFF
        # Insert the least significant bit of High into the most significant bit of Low
        bit_insert = 0x8000 if uVar1 else 0
        uVar2 = (uVar2 >> 1) | bit_insert
        iVar3 -= 1
        
    # Compute new High (LFSR feedback):
    # Shift previous High right by 1 and place the feedback bit at bit 3.
    # Feedback bit is the XOR of the original Low and the shifted Low's least significant bits.
    term_h_1 = extraout_DX >> 1
    term_h_2 = ((uVar2 ^ in_AX) & 1) << 3
    res_high = (term_h_1 | term_h_2) & 0xFFFF
    
    # Compute new Low:
    # Shift the original Low right by 1 and inject the previous High's LSB into bit 15.
    term_l_1 = in_AX >> 1
    term_l_2 = (1 if (extraout_DX & 1) else 0) << 15
    res_low = (term_l_1 | term_l_2) & 0xFFFF
    
    return res_low, res_high

# Correct PRNG state found via brute force (matches prefix "lactf{")
# High = 0xF, Low = 0x3fb5
l = 0x3fb5
h = 0xF

print(f"Decrypting with State: Low={l:04x}, High={h:x}")

flag = ""
for b in target:
    # 1. Update PRNG state
    l, h = fun_tick(l, h)
    
    # 2. Derive key byte (low 8 bits of Low state)
    key = l & 0xFF
    
    # 3. Decrypt byte
    flag += chr(b ^ key)

print("\nFlag found:")
print(flag)