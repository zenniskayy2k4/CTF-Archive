import socket
import itertools
import time
import sys
from sage.all import *

# --- CẤU HÌNH ---
HOST = 'amt.rs'  # <--- ĐIỀN IP SERVER
PORT = 33969             # <--- ĐIỀN PORT

def read_until(s, delim=b'\n'):
    data = b''
    while not data.endswith(delim):
        chunk = s.recv(1)
        if not chunk:
            break
        data += chunk
    return data

def get_samples(n_samples):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((HOST, PORT))
    except Exception as e:
        print(f"[-] Connection failed: {e}")
        return None, None, []

    samples = []
    try:
        line = read_until(s).decode()
        parts = line.split('=')[-1].strip().strip('()')
        n_str, e_str = parts.split(',')
        n = int(n_str)
        e = int(e_str)
        print(f"[+] Got n (len {n.bit_length()}): {n}")
    except Exception as e:
        print(f"[-] Error parsing n/e: {e}")
        s.close()
        return None, None, []

    print(f"[*] Collecting {n_samples} samples...")
    
    for i in range(n_samples):
        try:
            read_until(s, b'scramble the flag: ')
            s.sendall(b'0\n')
            
            while True:
                line_resp = read_until(s).decode().strip()
                if line_resp.startswith('c ='):
                    c = int(line_resp.split('=')[-1].strip())
                    samples.append(c)
                    break
        except:
            break
            
    print(f"[+] Finished collecting {len(samples)} samples.")
    s.close()
    return n, e, samples

def solve():
    # Số lượng mẫu: nên khoảng 150-300.
    # Nếu máy khỏe thì tăng lên, nhưng 200 là con số khá ổn.
    # Nếu chạy xong mà không ra, hãy chạy lại script để lấy bộ mẫu mới.
    n, e, ciphertexts = get_samples(200)
    
    if not ciphertexts or len(ciphertexts) < 2:
        print("[-] Not enough samples.")
        return

    print("[+] Setting up SageMath environment...")
    
    PRx = PolynomialRing(Zmod(n), names='x, y')
    x, y = PRx.gens()
    
    PRy = PolynomialRing(Zmod(n), names='y_val')
    y_val = PRy.gen()
    
    PR_F = PolynomialRing(Zmod(n), names='z')
    z = PR_F.gen()

    pairs = list(itertools.combinations(ciphertexts, 2))
    print(f"[+] Generated {len(pairs)} pairs. Cracking...")

    # Cấu hình Coppersmith
    # Bound lý thuyết: N^(1/9) ~ 227 bit. 
    # Delta thực tế ~ 256 bit. Ta hy vọng 29 bit đầu trùng nhau.
    LIMIT_X = 2**229 
    EPSILON = 0.035

    for idx, (c1, c2) in enumerate(pairs):
        if idx % 500 == 0:
            sys.stdout.write(f"\r    Checking pair {idx}/{len(pairs)}")
            sys.stdout.flush()

        # Short Pad Attack
        g1 = x**3 - c1
        g2 = (x + y)**3 - c2
        
        try:
            # 1. Tính Resultant
            res_poly = g1.resultant(g2, x)
            
            # 2. Chuyển về đơn biến (cách an toàn nhất)
            # Lấy hệ số của đa thức theo y
            coeffs = res_poly.coefficients()
            # Tạo lại đa thức trên vành PRy
            res_uni = sum(c * (y_val**i) for i, c in enumerate(coeffs))
            
            # Nếu đa thức hằng số hoặc bậc 0 -> bỏ qua
            if res_uni.degree() == 0: continue

            # 3. Tìm nghiệm nhỏ
            roots = res_uni.small_roots(X=LIMIT_X, beta=1.0, epsilon=EPSILON)
            
            if roots:
                delta = roots[0]
                if delta == 0: continue # Trùng mẫu
                
                print(f"\n\n[!] MATHEMATICAL HIT! Delta found: {delta}")
                
                # 4. Franklin-Reiter Attack
                p1 = z**3 - c1
                p2 = (z + delta)**3 - c2
                
                # Tính GCD
                pgcd = p1.monic().gcd(p2.monic())
                
                # Nếu bậc GCD là 1, nghĩa là ta đã tìm ra nghiệm duy nhất
                if pgcd.degree() == 1:
                    print("[+] GCD Degree is 1 -> Solution confirmed!")
                    
                    coeffs_gcd = pgcd.coefficients()
                    # pgcd = z + a => nghiệm m = -a
                    val = -coeffs_gcd[0] * pow(coeffs_gcd[1], -1, n)
                    m = int(val) % n
                    
                    # Recover Flag
                    # m = (flag << 256) + r
                    flag_int = m >> 256
                    
                    print("-" * 50)
                    print(f"[SUCCESS] Integer Message: {flag_int}")
                    
                    # Convert sang bytes & in RAW
                    try:
                        flag_bytes = flag_int.to_bytes((flag_int.bit_length() + 7) // 8, 'big')
                        print(f"[OUTPUT] HEX: {flag_bytes.hex()}")
                        print(f"[OUTPUT] RAW: {flag_bytes}")
                    except Exception as e:
                        print(f"[!] Could not convert to bytes (might be small int): {e}")
                    
                    print("-" * 50)
                    return # Dừng ngay khi tìm thấy nghiệm toán học hợp lý
                    
        except Exception:
            continue

    print("\n[-] Scan finished. No suitable pair found in this batch.")
    print("[-] Recommendation: Run again.")

if __name__ == "__main__":
    solve()