#!/usr/bin/env python3

from Crypto.Util.number import long_to_bytes
import sys

def egcd(a, b):
    """
    Sử dụng thuật toán Euclid mở rộng để tìm u, v sao cho:
    a*u + b*v = gcd(a, b)
    Trả về tuple (gcd, u, v)
    """
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

# --- 1. Đọc và phân tích file output.txt ---

print("[+] Đang đọc dữ liệu từ file output.txt...")
try:
    with open('output.txt', 'r') as f:
        lines = f.readlines()
except FileNotFoundError:
    print("[-] Lỗi: Không tìm thấy file 'output.txt'. Hãy chắc chắn file đó ở cùng thư mục với kịch bản này.")
    sys.exit(1)

# Lấy giá trị n từ dòng đầu tiên
try:
    n = int(lines[0].split('=')[1].strip())
except (IndexError, ValueError):
    print("[-] Lỗi: Không thể phân tích giá trị n từ dòng đầu tiên của file.")
    sys.exit(1)
    
# Tách các cặp (c, e) từ các dòng còn lại
ce_pairs = []
for line_num, line in enumerate(lines[1:], start=2):
    if line.strip():
        try:
            full_c_str = line.split('=')[1].strip()
            
            # e là số nguyên tố 32-bit nên gần như luôn có 10 chữ số.
            # 2**31 ~ 2.1e9 (10 chữ số), 2**32-1 ~ 4.2e9 (10 chữ số)
            c_str = full_c_str[:-10]
            e_str = full_c_str[-10:]
            
            c = int(c_str)
            e = int(e_str)
            ce_pairs.append((c, e))
        except (IndexError, ValueError):
            print(f"[-] Cảnh báo: Không thể phân tích dòng {line_num}. Bỏ qua.")

print(f"[+] Đã đọc thành công n và {len(ce_pairs)} cặp (c, e).")

# --- 2. Duyệt qua tất cả các cặp (c, e) để tìm cặp có cùng m ---

flag = []

print("[*] Bắt đầu tìm kiếm hai bản mã có cùng một thông điệp gốc...")
num_pairs = len(ce_pairs)
for i in range(num_pairs):
    for j in range(i + 1, num_pairs):
        # Lấy hai cặp (c, e) khác nhau
        c1, e1 = ce_pairs[i]
        c2, e2 = ce_pairs[j]

        # Áp dụng Common Modulus Attack
        g, u, v = egcd(e1, e2)

        if g != 1:
            continue  # Bỏ qua nếu e không nguyên tố cùng nhau (rất hiếm)

        try:
            # Tính m_candidate = (c1^u * c2^v) mod n
            # Hàm pow() của Python hỗ trợ số mũ âm, nó sẽ tự động tính nghịch đảo modular
            m_candidate = (pow(c1, u, n) * pow(c2, v, n)) % n
            flag_candidate_bytes = long_to_bytes(m_candidate)

            # --- 3. Kiểm tra xem ứng cử viên có phải là flag không ---
            # Dựa trên format flag phổ biến của các cuộc thi CTF
            if flag_candidate_bytes.startswith(b'ASIS'):
                flag.append(flag_candidate_bytes)
                print(f"[+] Flag là: {flag_candidate_bytes.decode()}")
                # sys.exit(0) # Thoát sau khi tìm thấy flag
        except Exception:
            # Bỏ qua nếu có lỗi tính toán hoặc giải mã (ví dụ: long_to_bytes lỗi)
            # Điều này xảy ra khi cặp (c, e) không tương ứng với cùng một m
            continue

if flag:
    print("\n[+] Đã tìm thấy các flag sau:")
    for f in flag:
        print(f"   - {f}")
else:
    print("\n[-] Đã thử tất cả các cặp nhưng không tìm thấy flag. Có thể giả định đã sai.")