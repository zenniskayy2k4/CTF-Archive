from Crypto.Util.number import long_to_bytes
import os
from sage.all import *

os.environ['TERM'] = 'linux'
os.environ['TERMINFO'] = '/usr/share/terminfo'

n = 2141771346571978206055777096296546941051995769481606440056894144304013650429328237178099130371616079442750032571713474466162151919967555380672317584136291188506417022786843105280471852200008422737862296304677100088505567316886766922362473604859628682045056333740840502097124203263967777089163009002593422061798936570792679968943213666586647661779029803192154100882572169940010936253172043578765768132703
c = 1621917139051691524673774758880466834919043816656893792507035286935477728352104653069765547393529194156963007711775885743000880277736160439871180815123052280359584613776164147127240115393495541387118782411690493659212814740522999563723389127680711189847732708868405892471107708655095158474016313711220997228551732390357219914343746793200996909869757089026402878281545681995023134428375651147231235564054
e = 65537
# Thiết lập cấu trúc p: 67*'6' + X + 67*'7'
# Trong đó X là tổ hợp '6'/'7' của 67 chữ số ở giữa
# Nếu ta coi '6' là cơ sở, X thực chất là số có 67 chữ số nhị phân (0 hoặc 1)
B = int("6" * 134 + "7" * 67) # Base: coi như toàn bộ 67 số giữa là '6'
k = 10**67
X_bound = int("1" * 67)       # Vì mỗi chữ số giữa chỉ tăng thêm tối đa 1 đơn vị

# Giải đa thức tìm nghiệm nhỏ
P = PolynomialRing(Zmod(n), names='x')
x = P.gen()

# f(X) = k*X + B = p = 0 (mod p)
# => X + B * k^-1 = 0 (mod p)
f = x + B * pow(k, -1, n)
f = f.monic()

print("[+] Đang chạy Coppersmith Attack...")
# Giảm beta xuống 0.4 để tìm ước p < sqrt(n)
roots = f.small_roots(X=X_bound, beta=0.4)

if roots:
    X_val = int(roots[0])
    p = k * X_val + B
    print(f"[!] Tìm thấy p: {p}")
    
    assert n % p == 0
    q = n // p
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    m = pow(c, d, n)
    
    print(f"[!] FLAG: {long_to_bytes(m).decode()}")
else:
    print("[-] Vẫn không tìm thấy nghiệm. Hãy kiểm tra lại n và c.")