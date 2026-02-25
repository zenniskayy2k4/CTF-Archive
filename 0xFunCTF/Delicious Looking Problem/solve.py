import re
from Crypto.Util.number import long_to_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from hashlib import sha256
from sympy.ntheory.residue_ntheory import discrete_log
from sympy.ntheory.modular import crt
import math

def solve():
    # 1. Đọc và lấy dữ liệu từ tệp output.txt
    try:
        with open('output.txt', 'r') as f:
            content = f.read()
    except FileNotFoundError:
        print("[-] Không tìm thấy tệp output.txt!")
        return

    # Lấy danh sách g, h, p bằng Regex
    gs = [int(x) for x in re.findall(r'g = (\d+)', content)]
    hs = [int(x) for x in re.findall(r'h = (\d+)', content)]
    ps = [int(x) for x in re.findall(r'p = (\d+)', content)]
    
    # Lấy ciphertext (ct)
    ct_match = re.search(r"ct\s*=\s*'([a-fA-F0-9]+)'", content)
    if not ct_match:
        # Nếu không tìm thấy bằng regex, thử tìm thủ công dòng cuối
        lines = content.strip().split('\n')
        last_line = lines[-1]
        if "ct =" in last_line:
            ct_hex = last_line.split("'")[1]
        else:
            print("[-] Không tìm thấy ciphertext trong file! Hãy mở output.txt kiểm tra xem có dòng ct = '...' không.")
            return
    else:
        ct_hex = ct_match.group(1)
    ct_bytes = bytes.fromhex(ct_hex)

    print(f"[*] Đã lấy được {len(gs)} mẫu dữ liệu.")
    
    # 2. Giải bài toán Logarithm rời rạc (DLP)
    remainders = []
    moduli = []
    
    print("[*] Đang giải DLP cho từng mẫu (có thể mất 1-2 phút)...")
    for i in range(len(gs)):
        # Tìm x sao cho g^x % p == h
        x = discrete_log(ps[i], hs[i], gs[i])
        remainders.append(x)
        moduli.append(ps[i] - 1)
        print(f"    [+] Sample #{i} xong.")

    # 3. Sử dụng Định lý số dư Trung hoa (CRT)
    # key_base là giá trị nhỏ nhất thỏa mãn hệ phương trình đồng dư
    key_base, _ = crt(moduli, remainders)
    full_lcm = 1
    for m in moduli:
        full_lcm = (full_lcm * m) // math.gcd(full_lcm, m)

    print(f"[*] CRT base tìm được: {key_base}")
    print(f"[*] LCM của các modulo: {full_lcm}")

    # 4. Brute-force n và độ dài key
    # Gợi ý từ chall là 'biased:3' và link video liên quan số 42
    print("[*] Đang tìm key chính xác bằng cách thử n và độ dài...")
    
    # Thử độ dài từ 33 đến 47 bytes (AES block là 16, ct là 48)
    for length in range(33, 48):
        # Tính n_limit dựa trên độ dài (để key không vượt quá số bit của độ dài đó)
        max_val = 1 << (length * 8)
        if key_base >= max_val:
            continue
            
        n_limit = (max_val - key_base) // full_lcm
        
        for n in range(n_limit + 1):
            real_key_long = key_base + n * full_lcm
            
            try:
                # Chuyển số nguyên thành chuỗi bytes
                test_key = real_key_long.to_bytes(length, 'big')
                
                # Tạo khóa AES từ SHA256 của key
                aes_key = sha256(test_key).digest()
                cipher = AES.new(aes_key, AES.MODE_ECB)
                
                # Giải mã
                decrypted = cipher.decrypt(ct_bytes)
                
                # Thử gỡ padding và kiểm tra flag
                try:
                    flag = unpad(decrypted, 16)
                    # Kiểm tra dấu hiệu của flag (thường bắt đầu bằng 0xFun hoặc KCSC)
                    if any(prefix in flag for prefix in [b'0x']):
                        print(f"\n" + "="*30)
                        print(f"[!] TÌM THẤY FLAG!")
                        print(f"[*] Độ dài key: {length}")
                        print(f"[*] Giá trị n: {n}")
                        print(f"[*] Key (hex): {test_key.hex()}")
                        print(f"[*] Flag: {flag.decode()}")
                        print("="*30)
                        return
                except:
                    continue
            except OverflowError:
                continue

    print("\n[-] Rất tiếc, không tìm thấy flag. Hãy kiểm tra lại dữ liệu đầu vào.")

if __name__ == "__main__":
    solve()