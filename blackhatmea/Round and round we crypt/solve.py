import struct
import zlib
import ctypes

key = [0x0b2b77d0, 0x837cdbaf, 0xa5c7a28d, 0x17db9019]
schedule = [
    0x23b4363b, 0x4a8920a0, 0x8a0b1752, 0xaceebe81,
    0x5ded16c4, 0x1cd777cd, 0xc86aadf2, 0x64459b0a,
    0xd55ad554
]
ciphertext_data = [
    0x36196a12, 0xb16b464a,
    0x3b2e6c9a, 0x5f9d2453,
    0xf42a66b0, 0x907ca2cf,
    0xa9288c6c, 0x2a6244f4,
    0xd479081b, 0x9a5ef180 
]

def decrypt_block_final(ct_v0, ct_v1, k, s):
    v0_ct = ctypes.c_uint32(ct_v0)
    v1_ct = ctypes.c_uint32(ct_v1)
    delta = ctypes.c_uint32(0x9e3779b9)
    k_ct = [ctypes.c_uint32(val) for val in k]
    s_ct = [ctypes.c_uint32(val) for val in s]
    v1 = ctypes.c_uint32(v0_ct.value ^ k_ct[2].value)
    v0 = ctypes.c_uint32(v1_ct.value - k_ct[3].value)
    for i in range(8, -1, -1):
        s_val = s_ct[i]
        shift2 = ctypes.c_uint32(-(s_val.value >> 3 & 7) - 5).value & 0x1f
        k2 = k_ct[(i + 1) & 3]
        temp = v1
        right_part2 = (temp.value >> shift2) | (temp.value << (32 - shift2))
        old_v1 = ctypes.c_uint32(v0.value ^ (temp.value + k2.value + right_part2))
        shift1 = ctypes.c_uint32(-(s_val.value & 7) - 3).value & 0x1f
        k1 = k_ct[i & 3]
        right_part1 = (old_v1.value >> shift1) | (old_v1.value << (32 - shift1))
        old_v0 = ctypes.c_uint32(temp.value - k1.value - (s_val.value ^ delta.value) - right_part1)
        v0 = old_v0
        v1 = old_v1
    return v0.value, v1.value

decrypted_bytes = b""
for i in range(0, len(ciphertext_data), 2):
    ct_v0 = ciphertext_data[i]
    ct_v1 = ciphertext_data[i+1]
    pt_v0, pt_v1 = decrypt_block_final(ct_v0, ct_v1, key, schedule)
    decrypted_bytes += struct.pack('<II', pt_v0, pt_v1)

full_flag = decrypted_bytes[:36]

expected_crc = 0xd98851cb

calculated_crc = zlib.crc32(full_flag) ^ 0xffffffff

print(f"[+] Flag được trích xuất (36 bytes): {full_flag.decode('ascii', errors='ignore')}")
print(f"[+] CRC32 mong muốn: {hex(expected_crc)}")
print(f"[+] CRC32 tính được: {hex(calculated_crc)}")

if calculated_crc == expected_crc:
    print("\n[SUCCESS] CRC32 khớp! Flag đã tìm thấy là chính xác.")
    print(f"FLAG: {full_flag.decode('ascii', errors='ignore')}")
else:
    print("\n[FAILURE] CRC32 không khớp.")