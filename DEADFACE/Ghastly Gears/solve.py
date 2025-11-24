def solve_ghastly_gears():
    ciphertext = """
Fsqp: rhurk415
Ie: ljjkhwaoj
Vygplkc: dr: rrudok ld tig hwuw

---

ne,

ajp rge hlpjy nayx gvt dakljn zdfpth nz enxe qoga. rip tcqe tlkmz ikyff hwu exnvzxrz—jv’w gst ceuyz yeltwo.

zltq, kubvm dazsixzfz rafpc jp xmk vxdpe.hmj. fcbdq ae c oje wa amfgexisly?

"mou dpq npxcee vpkel nca nzsu — xutm vpmis jisbfn fl hfz: ikhloknq{uw0jll_i3s3q_e1h}"

vxd ehft zx co’p hmqquxfta, lff mdk cgir emv ujhc rvdn etrwg ujtgvpfa cscs.

wqwq yr xv qho bflc nqui."""

    # 1. Tìm vị trí của 'ikhloknq' (tương ứng với 'deadface')
    target = "ikhloknq"
    start_index = ciphertext.find(target)
    
    # 2. Chúng ta biết khóa tại ký tự 'i' của 'ikhloknq' là 'F' (giá trị 5)
    #    Gọi khóa ban đầu tại ký tự đầu tiên của văn bản là K0.
    #    Theo quy luật tăng trên MỌI ký tự: Key_at_index = (K0 + index) % 26
    #    Suy ra: 5 = (K0 + start_index) % 26
    #    => K0 = (5 - start_index) % 26
    
    k0 = (5 - start_index) % 26
    
    print(f"[*] Found '{target}' at index {start_index}")
    print(f"[*] Calculated starting key (K0): {k0} (corresponding letter '{chr(ord('A') + k0)}')")

    # 3. Giải mã toàn bộ văn bản với K0 tìm được
    plaintext = []
    current_key = k0
    
    for char in ciphertext:
        if 'a' <= char <= 'z':
            # Giải mã chữ thường
            p = (ord(char) - ord('a') - current_key + 26) % 26
            plaintext.append(chr(ord('a') + p))
        elif 'A' <= char <= 'Z':
            # Giải mã chữ hoa
            p = (ord(char) - ord('A') - current_key + 26) % 26
            plaintext.append(chr(ord('A') + p))
        else:
            # Giữ nguyên ký tự không phải chữ cái
            plaintext.append(char)
        
        # QUAN TRỌNG: Khóa luôn tăng bất kể ký tự là gì
        current_key = (current_key + 1) % 26

    return "".join(plaintext)

# Chạy và in kết quả
decrypted_msg = solve_ghastly_gears()
print("\n----- Decrypted Message -----\n")
print(decrypted_msg)

# Trích xuất flag từ kết quả
import re
match = re.search(r"deadface\{[^\}]+\}", decrypted_msg)
if match:
    print(f"\nFLAG: {match.group(0)}")
else:
    print("\nFLAG NOT FOUND. Please check the logic.")