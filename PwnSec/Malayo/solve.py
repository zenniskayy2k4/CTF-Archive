import z3
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import base64

print("[*] Bắt đầu giải các ràng buộc (phiên bản đã sửa lỗi logic cuối cùng)...")

f = [z3.Int(f'f_{i}') for i in range(36)]
s = z3.Solver()

for i in range(36):
    s.add(f[i] >= 32, f[i] <= 126)

# === Ràng buộc từ Uu(f) ===
s.add(f[0] == ord('f'))
s.add(f[1] == ord('l'))
s.add(f[2] == ord('a'))
s.add(f[3] == ord('g'))
s.add(f[4] == ord('{'))
s.add(f[5] == ord('U'))
s.add(f[6] == ord('_'))

# === Ràng buộc từ uU(f) ===
s.add(f[7] * 7 == 525)
s.add(f[8] * 17 - 10 == (252 ^ 933))
s.add(f[9] == f[8])
s.add(f[28] == f[8])
s.add(f[31] == f[8])
s.add((f[10] - 112) * 1000 + (f[11] - 95) == 0)
s.add(f[14] == f[11])
s.add(f[19] == f[11])
s.add(f[23] == f[11])
s.add(f[26] == f[11])
s.add(f[32] == f[11])
s.add(f[12] == 49)
s.add(f[33] == f[12])
s.add((f[13] + 10) * 5 == (553 ^ 95))
s.add(f[15] == f[13])
s.add(f[18] == f[13])
s.add(f[34] == f[13])

# === Ràng buộc từ UU(f) ===
s.add(f[16] * 2 - 12 - 196 == 0)
s.add(f[17] == 52)
s.add(f[21] == f[17])
s.add(f[29] == f[17])
s.add(f[20] * 3 - 357 == 0)

# SỬA LỖI CUỐI CÙNG: f[22] = f[20] + 2
s.add(f[22] == f[20] + 2) 

s.add(f[24] == 48)
s.add(f[25] == f[22] - 7)
s.add(z3.Or(f[27] == 76, f[30] == 118)) # Giữ lại Or để Z3 tự tìm nhánh đúng

# === Ràng buộc từ UUu(f) ===
s.add(f[35] == ord('}'))
s.add(z3.Sum(f) == 3217)

if s.check() == z3.sat:
    m = s.model()
    result = [m.evaluate(f[i]).as_long() for i in range(36)]
    flag = "".join(map(chr, result))
    print(f"[*] Z3 tìm thấy flag tiềm năng: {flag}")

    print("\n[*] Đang xác minh lại với phần mã hóa AES...")
    flag_content = flag[7:35]
    key_part = flag_content[:17]
    plaintext = flag_content[17:]
    key = hashlib.sha256(key_part.encode()).digest()
    iv = b'PWNSEC_CHALLENGE'
    expected_ciphertext = base64.b64decode('jNtv1ielcDMRvnTLzB2hrg==')
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = pad(plaintext.encode(), AES.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)
    
    if ciphertext == expected_ciphertext:
        print("[+] Xác minh AES thành công!")
        print(f"\n[+] Flag cuối cùng là: {flag}")
    else:
        print("[-] Xác minh AES thất bại.")
else:
    print("[-] Z3 không tìm thấy lời giải (unsat).")