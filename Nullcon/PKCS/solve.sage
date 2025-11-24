# --- BƯỚC 1: NHẬP CÁC GIÁ TRỊ TỪ SERVER ---

FLAG_LEN = 115
n = 105919681136230345991185824445933496776363656608719564744526618188106510192324293094347074623337961039264192588551105643100926527521162528980369191383324421335368012518179079152987546699320283654086434143279854692647914557754742377636808166221157533507228277945184700133401799110252422259771821523588744962879
c1_hex = "31683bb8bdddc5bdca22fb9ab10eb6a9b99828d5cc7d09e9710f45727ef7273932c20fa773abb91bbd97b5e717fee7cf0c2c89557c945c140d2fd12b876ac557d11b3027f3a835ffe8d77787280251c1dd2794840d8fe1bacc538dd2cead2c470de77b2bb3afbe7bb683577a4637093c4e8984a0e8f93fc1f55d30348a22d01e"
c2_hex = "5b24df1e8e211ac26b45405eb02d7bdcd16c4e6410530279e01b9307f4b01e2d5447a4d31f152e6fbec10f5148c4b544d025b61c8c498e4e06c48971ff69d2b7bede0134037af59485fcf976d2541e2a7286a97b8e08c0baf613c77236d0221467664aad6c941c03f0026a2353891598edae739d8a5ed0419ec11ed787623f2d"

# Chuyển đổi hex sang số nguyên
c1 = int(c1_hex, 16)
c2 = int(c2_hex, 16)
e = 3
BIT_LEN = 1024
k = BIT_LEN // 8 # Độ dài khoá tính bằng byte (128)

# --- BƯỚC 2: THIẾT LẬP CÁC ĐA THỨC ---
# Định nghĩa vành đa thức trên Z_n
# Biến: x đại diện cho flag, y đại diện cho PS1, z đại diện cho PS2
P.<x, y, z> = Zmod(n)[]

# Cấu trúc thông điệp m = 0x0002 || PS || 0x00 || flag
# m = 2*256^(k-2) + PS * 256^(len(flag)+1) + flag
# Đặt K = 2*256^(k-2) và S = 256^(len(flag)+1)
K = 2 * 256**(k - 2)
S = 256**(FLAG_LEN + 1)

# Đa thức cho mã hóa thứ nhất: (K + y*S + x)^e - c1 = 0 mod n
p1 = (K + y*S + x)^e - c1
# Đa thức cho mã hóa thứ hai: (K + z*S + x)^e - c2 = 0 mod n
p2 = (K + z*S + x)^e - c2

# --- BƯỚC 3: KHỬ BIẾN FLAG (x) BẰNG RESULTANT ---
# Tính resultant của p1 và p2 theo biến x để loại bỏ x.
# Kết quả là một đa thức R(y,z) = 0 mod n
print("[INFO] Computing resultant to eliminate x (flag)...")
R_yz = p1.resultant(p2, x)
print("[SUCCESS] Resultant computed.")

# --- BƯỚC 4: TÌM NGHIỆM NHỎ CỦA ĐA THỨC HAI BIẾN ---
# Bây giờ chúng ta cần tìm nghiệm (y0, z0) nhỏ cho R_yz(y,z) = 0 mod n.
# Đây là phần phức tạp nhất, sử dụng phương pháp Coppersmith cho hai biến.
# Hàm `small_roots` dưới đây thực hiện điều này.

# Hàm này triển khai phương pháp của Coppersmith để tìm nghiệm nhỏ.
# Nó dựa trên việc xây dựng một dàn (lattice) và tìm vector ngắn nhất.
def small_roots(p, bounds, m=1, d=None):
    if not d:
        d = p.degree()

    R = p.parent()
    N = R.characteristic()

    if isinstance(p, MPolynomial_libsingular):
        x, y = R.gens()
        p_xy = p
    else:
        # Hỗ trợ đa thức một biến
        x, = R.gens()
        y = x
        p_xy = p

    X, Y = bounds

    # heuristic for number of monomials
    d_ = d
    m_ = m
    while True:
        if d_ < 1:
            return []
        
        t = int((d_ * (d_ + 1) / 2) * m_ * (m_ + 1) / 2)
        if t > 70: # matrix size limit
            d_ -= 1
            continue

        try:
            M = []
            for i in range(m_ + 1):
                for j in range(m_ - i + 1):
                    for k in range(d_ + 1):
                        for l in range(d_ - k + 1):
                            gg = x^k * y^l * p_xy^(i) * N^j
                            M.append(gg)
            
            p_ = M[0].parent()
            x_, y_ = p_.gens()
            
            B = Matrix(ZZ, len(M), len(M))
            
            for i in range(len(M)):
                for j in range(len(M)):
                    B[i,j] = M[i].coefficient(x_**j, y_**j)
            
            B = B.LLL()
            
            new_p = 0
            for i in range(len(M)):
                new_p += B[0,i] * M[i] / (X**i) / (Y**i)
            
            new_p = new_p(x*X, y*Y)
            roots = new_p.roots()
            
            return roots
        except Exception as e:
            d_ -= 1
            continue

# Độ dài của phần đệm ngẫu nhiên PS
ps_len = k - 3 - FLAG_LEN

# Đặt giới hạn trên cho các giá trị y (ps1) và z (ps2).
# Giá trị của PS nhỏ hơn 256^ps_len.
bounds = (256**ps_len, 256**ps_len)

print(f"[INFO] Searching for small roots (y, z) with bounds {bounds}...")
# Tìm nghiệm. m và d là các tham số cho thuật toán, có thể cần điều chỉnh
# nếu không tìm thấy nghiệm.
roots = small_roots(R_yz, bounds, m=2, d=2)

if not roots:
    print("[ERROR] Could not find roots. Try adjusting m and d parameters in small_roots.")
else:
    print(f"[SUCCESS] Found potential roots: {roots}")

    # --- BƯỚC 5: KHÔI PHỤC FLAG ---
    for y0, z0 in roots:
        # Lấy giá trị nguyên của nghiệm
        ps1_found = Integer(y0)
        
        # Thay giá trị ps1 tìm được vào đa thức ban đầu
        p_final = p1.subs(y=ps1_found)
        
        # Bây giờ p_final là đa thức một biến x. Tìm nghiệm của nó.
        flag_roots = p_final.univariate_polynomial().roots()
        
        if flag_roots:
            for r in flag_roots:
                # r[0] là nghiệm, r[1] là bội của nghiệm
                flag_int = r[0]
                
                # Chuyển số nguyên về dạng byte
                from Crypto.Util.number import long_to_bytes
                flag = long_to_bytes(int(flag_int))
                
                # In kết quả
                print("-" * 50)
                print(f"[SUCCESS] Found possible flag: {flag}")
                # Kiểm tra xem có phải flag hợp lệ không (thường là printable)
                try:
                    print(f"[DECODED] {flag.decode('utf-8')}")
                except:
                    print("[INFO] Flag is not valid UTF-8, but here are the bytes.")
                print("-" * 50)