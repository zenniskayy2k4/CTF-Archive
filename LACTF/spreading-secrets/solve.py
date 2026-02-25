from Crypto.Util.number import long_to_bytes
from sage.all import *
import time

# 1. Cấu hình
pari.allocatemem(4*10**9) # Cấp 4GB RAM cho thư viện tính toán

# Thông số đề bài
p = 12670098302188507742440574100120556372985016944156009521523684257469947870807586552014769435979834701674318132454810503226645543995288281801918123674138911
y1 = 6435837956013280115905597517488571345655611296436677708042037032302040770233786701092776352064370211838708484430835996068916818951183247574887417224511655

a = 4378187236568178488156374902954033554168817612809876836185687985356955098509507459200406211027348332345207938363733672019865513005277165462577884966531159
b = 5998166089683146776473147900393246465728273146407202321254637450343601143170006002385750343013383427197663710513197549189847700541599566914287390375415919
c = 4686793799228153029935979752698557491405526130735717565192889910432631294797555886472384740255952748527852713105925980690986384345817550367242929172758571
d = 4434206240071905077800829033789797199713643458206586525895301388157719638163994101476076768832337473337639479654350629169805328840025579672685071683035027

# Thiết lập Vành đa thức
R = PolynomialRing(GF(p), 'S')
S = R.gen()

def f(x):
    return (a * x**3 + b * x**2 + c * x + d)

# 2. Xây dựng đa thức P(S)
poly = S
current_state = S
print("[+] Đang xây dựng đa thức (bậc 19683)...")
for i in range(9):
    current_state = f(current_state)
    poly += current_state
poly -= y1

# 3. Kỹ thuật GCD (Quan trọng)
print(f"[+] Bắt đầu tính S^p mod Poly. Bước này tốn khoảng 1-2 phút...")
t0 = time.time()

# Tính H = S^p mod P(S) bằng lũy thừa nhị phân (binary exponentiation)
# SageMath thực hiện phép này rất nhanh nếu gọi đúng hàm pow
H = pow(S, p, poly)

print(f"[+] Tính xong lũy thừa trong {time.time() - t0:.2f}s. Đang tính GCD...")

# Tính GCD(P(S), H - S) để lọc ra các nghiệm tuyến tính
G = poly.gcd(H - S)

print(f"[+] Đa thức kết quả GCD có bậc: {G.degree()}")

# 4. Lấy nghiệm từ đa thức bậc thấp
roots = G.roots()

if roots:
    print(f"[+] Tìm thấy {len(roots)} nghiệm!")
    for val, _ in roots:
        try:
            flag = long_to_bytes(int(val))
            print(f"[!] FLAG: {flag.decode()}")
        except:
            print(f"[!] Raw Root: {val}")
else:
    print("[-] Không tìm thấy nghiệm nào (Có thể sai thông số?).")