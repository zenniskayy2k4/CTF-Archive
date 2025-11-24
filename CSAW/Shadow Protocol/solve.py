import ctypes
import sys


TIMESTAMP = 1915532940
ENCRYPTED_FLAG_HEX = "27C4817F48267DD83684963B59672ACD23E8D5601F362BD43DE8907A1B652BC074DBD5571A6744C077C5D73C1A3C2ADA1BD9D03F74612FD03DCA"

sbox = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]
# =====================================================

# Hàm helper
def u32(n):
    return n & 0xFFFFFFFF

def u64(n):
    return n & 0xFFFFFFFFFFFFFFFF

def ror(val, bits, size=32):
    return ((val >> bits) | (val << (size - bits))) & ((1 << size) - 1)

def reproduce_rand_64(seed):
    try:
        libc = ctypes.CDLL("libc.so.6")
    except OSError:
        print("Lỗi: Không tìm thấy 'libc.so.6'.")
        sys.exit(1)
    libc.srand.argtypes = [ctypes.c_uint]
    libc.rand.restype = ctypes.c_int
    libc.srand(seed)
    rand1 = libc.rand()
    rand2 = libc.rand()
    return u64((rand1 << 32) | rand2)

def reproduce_shadow_mix(rand_64bit):
    shadow_mix_result = 0
    # Vòng lặp từ 0 đến 0x15 (21), tương ứng với các node lá
    for i in range(22):
        leaf_value = 0
        ivar1 = i * -3 + 63

        # Triển khai ĐẦY ĐỦ logic của C, bao gồm cả trường hợp đặc biệt
        if ivar1 < 2:
            if ivar1 == 1: # Trường hợp này không bao giờ xảy ra với i nguyên
                 leaf_value = (rand_64bit * 2) & 6 | 1
            elif ivar1 == 0: # <-- LỖI NẰM Ở ĐÂY
                 leaf_value = ((rand_64bit & 1) << 2) | 3
            else: # ivar1 < 0
                 leaf_value = 7
        else:
            shift_amount = (ivar1 - 2) & 0x3f
            leaf_value = (rand_64bit >> shift_amount) & 7
        
        # Logic từ shadow_tree_mix
        shadow_mix_result = u64((shadow_mix_result << 3) | leaf_value)
        
    return shadow_mix_result
# ======================================================

def reproduce_shadow_protocol(shadow_mix_result):
    local_44 = u32(shadow_mix_result >> 32)
    local_40 = u32(shadow_mix_result)
    constants = [0xa5a5c3c3, 0x5a5a9696, 0x3c3ca5a5, 0xc3c35a5a]
    for i in range(8):
        uVar3 = local_44
        b0 = local_40 & 0xff
        b1 = (local_40 >> 8) & 0xff
        b2 = (local_40 >> 16) & 0xff
        b3 = (local_40 >> 24) & 0xff
        sbox_res = u32(sbox[b0] | (sbox[b1] << 8) | (sbox[b2] << 16) | (sbox[b3] << 24))
        uVar1 = u32(sbox_res ^ constants[i % 4])
        uVar4 = u32(((i + 1) * 0x1337beef) ^ local_44)
        local_44 = local_40
        rot_amount_right = (0x1d - i) & 0x1f
        rotated_val = ror(uVar1, rot_amount_right)
        local_40 = u32(u32(rotated_val + uVar4) ^ uVar3)
    combined = u64((local_44 << 32) | local_40)
    uVar2 = u64(combined ^ 0xdeadbeefcafebabe)
    rotated_uVar2 = u64((uVar2 << 17) | (uVar2 >> 47))
    keystream = u64(rotated_uVar2 + 0x1234567890abcdef)
    return keystream

def decrypt_flag(encrypted_hex, keystream):
    try:
        encrypted_bytes = bytes.fromhex(encrypted_hex)
    except ValueError:
        return "[Lỗi chuỗi HEX]"
    key_bytes = keystream.to_bytes(8, 'little')
    decrypted_bytes = bytearray()
    for i in range(len(encrypted_bytes)):
        decrypted_byte = encrypted_bytes[i] ^ key_bytes[i % 8]
        decrypted_bytes.append(decrypted_byte)
    return decrypted_bytes.decode('utf-8')

def main():
    print(f"[+] Using timestamp: {TIMESTAMP}")
    rand_64bit = reproduce_rand_64(TIMESTAMP)
    print(f"[+] Reproduced rand 64-bit (local_d8): {rand_64bit:#x}")
    shadow_mix_result = reproduce_shadow_mix(rand_64bit)
    print(f"[+] Reproduced shadow mix result (local_f0): {shadow_mix_result:#x}")
    keystream = reproduce_shadow_protocol(shadow_mix_result)
    print(f"[+] Reproduced encryption key (local_c8): {keystream:#x}")
    print(f"\n[+] Encrypted flag (HEX): {ENCRYPTED_FLAG_HEX}")
    decrypted_flag = decrypt_flag(ENCRYPTED_FLAG_HEX, keystream)
    print("\n=====================================")
    print(f"[*] FLAG: {decrypted_flag}")
    print("=====================================")

if __name__ == "__main__":
    main()