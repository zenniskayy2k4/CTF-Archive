import urllib.request
import urllib.parse
import json
import hashlib
from Crypto.Cipher import AES

# ==================== DATA ====================
p = 129403459552990578380563458675806698255602319995627987262273876063027199999999
enc_flag = bytes.fromhex("f6ca1f88bdb8e8dda17861b91704523f914564888c7138c24a3ab98902c10de5")

# Mã nguồn SageMath sẽ được gửi lên server để chạy BSGS trên Jacobian Genus 2
sage_code = """
import sys

p = 129403459552990578380563458675806698255602319995627987262273876063027199999999
F = GF(p)
R.<x> = PolynomialRing(F)

f_coeffs =

# Khởi tạo đường cong
f = sum(F(c) * x^i for i, c in enumerate(f_coeffs))
try:
    C = HyperellipticCurve(f)
    J = C.jacobian()
except Exception as e:
    print(f"k_result=ERROR: {e}")
    sys.exit(0)

# Dữ liệu Mumford của G và Q
G_u =
G_v =
Q_u =
Q_v =

uG = sum(F(c)*x^i for i, c in enumerate(G_u))
vG = sum(F(c)*x^i for i, c in enumerate(G_v))
uQ = sum(F(c)*x^i for i, c in enumerate(Q_u))
vQ = sum(F(c)*x^i for i, c in enumerate(Q_v))

DG = J(uG, vG)
DQ = J(uQ, vQ)

# Thuật toán BSGS siêu tốc (Quét khoảng 2^36)
def bsgs_jacobian(G, Q, bound):
    m = ceil(sqrt(bound))
    table = {}
    cur = 0*G
    for i in range(m):
        try:
            u, v = cur.mumford()
            table = i
        except: pass
        cur += G
    
    factor = -(m*G)
    cur = Q
    neg_cur = -Q
    for j in range(m):
        try:
            u, v = cur.mumford()
            key = (tuple(u.list()), tuple(v.list()))
            if key in table: return j*m + table
        except: pass
        try:
            u, v = neg_cur.mumford()
            key = (tuple(u.list()), tuple(v.list()))
            if key in table: return -(j*m + table)
        except: pass
        cur += factor
        neg_cur += factor
    return None

k = bsgs_jacobian(DG, DQ, 2^36)
if k is not None:
    print(f"k_result={k}")
else:
    print("k_result=NOT_FOUND")
"""

def decrypt_flag(k_int):
    # k_int có thể âm do quét 2 chiều trong BSGS, ta lấy giá trị tuyệt đối
    k_int = abs(k_int)
    print(f"\n Đang tiến hành vét cạn cơ chế tạo khóa AES với k = {k_int}...")
    derivations =[]
    
    # 1. Thử khóa dưới dạng String
    s_k = str(k_int).encode()
    derivations.append(hashlib.sha256(s_k).digest())
    derivations.append(hashlib.md5(s_k).digest())
    derivations.append(hashlib.md5(s_k).hexdigest().encode())
    
    # 2. Thử khóa dưới dạng Bytes trực tiếp
    try:
        b_k = k_int.to_bytes(max(1, (k_int.bit_length() + 7) // 8), 'big')
        derivations.append(hashlib.sha256(b_k).digest())
        derivations.append(hashlib.md5(b_k).digest())
        
        # Nếu byte k quá ngắn, chèn padding null bytes
        if len(b_k) <= 16:
            derivations.append(b_k.rjust(16, b'\0'))
            derivations.append(b_k.ljust(16, b'\0'))
        if len(b_k) <= 32:
            derivations.append(b_k.rjust(32, b'\0'))
            derivations.append(b_k.ljust(32, b'\0'))
    except Exception:
        pass
        
    # Duyệt qua các format chiều dài (16 bytes, 24 bytes, 32 bytes)
    for key in derivations:
        keys_to_try =[]
        if len(key) in (16, 24, 32): keys_to_try.append(key)
        if len(key) > 16: keys_to_try.append(key)
        if len(key) < 16: keys_to_try.append(key.ljust(16, b'\0'))
        
        for dkey in keys_to_try:
            # Bài này có thể dùng ECB hoặc CBC có IV=0
            for mode in [AES.MODE_ECB, AES.MODE_CBC]:
                try:
                    if mode == AES.MODE_ECB:
                        cipher = AES.new(dkey, mode)
                        pt = cipher.decrypt(enc_flag)
                    else:
                        cipher = AES.new(dkey, mode, iv=b'\x00'*16)
                        pt = cipher.decrypt(enc_flag)
                    
                    if b"BITSCTF{" in pt or b"bitsctf{" in pt or b"CTF{" in pt:
                        print(f"\n BINGO! TÌM THẤY FLAG!")
                        print(f"      Thuật toán: {'AES-ECB' if mode == AES.MODE_ECB else 'AES-CBC'}")
                        print(f"      Key (Hex): {dkey.hex()}")
                        print(f"      -> Flag: {pt.decode('utf-8', 'ignore')}")
                        return True
                except Exception:
                    pass
    return False

def main():
    print("==========================================================")
    print(" ĐƯỜNG CONG HYPERELLIPTIC BẬC 6 (GENUS 2) - BITSCTF")
    print(" Script sẽ tự động gửi mã SageMath lên SageCell API để")
    print(" xử lý tính toán cực nặng trên Jacobian thay cho máy bạn...")
    print("==========================================================\n")
    
    url = "https://sagecell.sagemath.org/"
    data = urllib.parse.urlencode({
        'code': sage_code,
        'accepted_tos': 'true'
    }).encode('utf-8')
    
    try:
        print(" Đang giao tiếp với máy chủ đám mây SageCell...")
        print(" Việc tìm kiếm Baby-Step Giant-Step sẽ tốn khoảng 10 - 20 giây...")
        req = urllib.request.Request(url, data=data)
        with urllib.request.urlopen(req, timeout=45) as response:
            res_text = response.read().decode('utf-8')
            res_json = json.loads(res_text)
            
            if not res_json.get('success', False):
                print(" Máy chủ SageCell báo lỗi do timeout!")
                return
                
            stdout = res_json.get('stdout', '')
            k_str = None
            for line in stdout.split('\n'):
                if line.startswith("k_result="):
                    k_str = line.split("=").strip()
            
            # Nếu tìm ra khóa
            if k_str and k_str.lstrip('-').isdigit():
                k_int = int(k_str)
                print(f" QUÁ TUYỆT VỜI! SageCell đã quét thành công khóa k = {k_int}")
                
                # Gọi thẳng thuật toán giải mã cục bộ
                if not decrypt_flag(k_int):
                    print(" Khóa k đúng, nhưng việc bẻ mã AES thất bại (Cần kiểm tra lại định dạng tạo khóa).")
            else:
                print(f" Rất tiếc, máy chủ không tìm ra khóa nhỏ. Output:\n{stdout}")
                
    except Exception as e:
        print(f" Lỗi mạng hoặc server quá tải: {e}")

if __name__ == "__main__":
    main()