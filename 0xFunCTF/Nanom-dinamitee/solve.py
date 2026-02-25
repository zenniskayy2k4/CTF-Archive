import struct

# Dữ liệu Hex dump từ file bạn cung cấp ban đầu
hex_data = """
e3 31 62 29 4c ad 63 af 0b 59 4b 39 6a 13 91 68
48 9e d5 a2 7f 6a dd f9 46 d2 21 d8 e1 33 da 68
3a 49 e0 0d c2 50 98 4c ce 03 06 93 bd 7a 1a 07
e1 1d 3a cb 20 4b 02 18 44 0e c3 55 b9 37 03 06
2e c0 f4 40 ec e5 85 fa 35 bc a7 f9 72 cd 45 a6
e2 6c 5d 08 5e 6e 58 30 7a 68 0f b5 c8 0f b0 83
ea 08 bf 7a 0b ed 92 d3 99 2d 2a d3 81 52 b1 41
d6 30 d1 1a 99 27 7d ca 37 3b ad 72 28 2e db e3
02 27 f1 06 ba d6 aa da ca d6 b7 4a 19 3f 72 81
37 7b 9a 5a f9 31 f8 ac bd b3 47 70 b4 3d 38 84
d0 7d 92 3a 9a 67 44 f3 ec c3 52 69 11 9a b9 ef
6a 6a 86 5c 95 50 24 ab b7 4e 79 6d cc 06 1f 55
66 61 26 18 5e 75 07 1d 4c 75 3b 73 e3 83 0d 7a
b1 3c 64 6e 7c 9a 6c a0 b9 0b 94 68 6f 53 c7 fc
ea 99 2e a9 4e 92 be 1a e1 ce 42 da a9 33 6c a0
4b f5 2f 05 9d 9b aa da 33 0f a6 6f cf 7f db bf
8a 79 25 1f 7a 7d 09 a8 8c 27 34 41 82 f0 99 ad
6c 5a 24 fb 54 95 bb 30 0b 91 dc 4d 66 1e 19 f3
6a 0a f5 bd d6 fb 3f f0 12 4d a3 f6 e4 1f c3 31
2d e1 a0 26 0f 88 dc 31 4e 5b c2 f9 be 81 9c 5a
"""

# Chuyển đổi bytes thành list các số nguyên 64-bit (Little Endian)
bytes_data = bytes.fromhex(hex_data.replace('\n', ' '))
target_hashes = list(struct.unpack(f'<{len(bytes_data)//8}Q', bytes_data))[:40]

def calc_hash(char_val, seed):
    # FNV-1a variation logic
    prime = 0x100000001b3
    mask = 0xFFFFFFFFFFFFFFFF
    
    val = (seed ^ char_val) & mask
    val = (val * prime) & mask
    val = (val ^ (val >> 32)) & mask
    return val

flag = ""
# Seed ban đầu lấy từ tham số thứ 3 trong hàm FUN_0010131b
current_seed = 0xcbf29ce484222325

print("Dang giai ma voi co che Chained Hash...")

for i, target in enumerate(target_hashes):
    found = False
    # Thử các ký tự in được
    for c in range(32, 127): 
        if calc_hash(c, current_seed) == target:
            flag += chr(c)
            found = True
            # QUAN TRỌNG: Cập nhật seed cho vòng lặp sau bằng chính hash mục tiêu hiện tại
            # (Vì hash tính ra == target, nên dùng target làm seed mới luôn)
            current_seed = target 
            break
    
    if not found:
        flag += "?"
        # Nếu không tìm thấy, vẫn gán seed = target để hy vọng giải tiếp được các ký tự sau
        current_seed = target

print(f"\nFlag tim duoc: {flag}")