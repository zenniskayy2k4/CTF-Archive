from Crypto.Util.number import long_to_bytes

# --- Dán các giá trị bạn nhận được từ script Python vào đây ---
n = 19824096289779707719070176420219404405975649576289360987337156942920640560947474203861545728776477068453316251743489488818575438139389137390001680576578942253185160551767561171930281687293775058687322920299688926107940313195563114987832411719502250028706236615699307065888267859479631783550915905832915046079116268787108565358170728204039019062479513313703326180686353871642215088776936705823333814666495676643533438721282771503090022914558511887457910263404506538263135239294720017462969027796092654622526393241408150198264487853704136390823516156295428991324911247541717694642575136926009399225564894472506595944743
c1 = 3828596688153066544693415470865404558724555361314605446099340321380236719044732313612043329438834413438764678595312161601329257822810385456565236162718351421979686602351017331245965941134251246066031849005852472384625356920727258991614360638616433978104804514071486080516481616719850495567238190860900501101702278344872041645259466205248592254841584586631814471751641281503871664074010212629429028985332101230771838420609092782254173364249416340607195181365532926536289128043495785488312228835836669412535599728029105182096268760716512588273358562594454291780102423209556230383032934022262657861838020315779795566924
c2 = 3828596688153066544693415470865404558722854676008156426178708980555402281334295944492431024910192627566523264769680269402736618318691706923074542730917756360653425292571818460555700216859773472394140604978286592993720309971541994873928623981096533594607420400389602687459348709925762355268034222561949223154182302505834891527064010043011378951663058772984902996036972751292492243212525744083642161707534993203916553098156119006490496151502890952169398652630626524256092961577645686829514543593951568906670715541943790913029413444039619022255529386862142822988458754707588173216290576951362112060566577832862506207924
c3 = 3828596688153066544693415470865404558734789144614755796242302350897475313346662464151954189611841158947562803098609862649431953938793812852993745263890528301951612464171260785793876097654298726265750757652324817540329341688508513450752851156285746115863466067968773854754574952984880004046435436742840923360414397731175290287536747744895764626115186943271613321593226630773828283917882862247942346304230949043166693341265253554234623335099197737670642777557023361355057687798517238348719511291866558824622064001968312596505553507796142202634822164666300725547737482775238945208309696060355748265039907896049806056116

bits = 256
K = 2^bits

print("[+] Bước 1: Định nghĩa đa thức trên vành số nguyên ZZ.")
R_int.<F, x_var, y_var> = PolynomialRing(ZZ)
p1 = (F + x_var)^3 - c1
p2 = (F + y_var)^3 - c2

print("[+] Bước 2: Đang tính resultant để loại bỏ F...")
g_int = p1.resultant(p2, F)
print("[+] Hoàn tất.")

P_ZZ.<x, y> = PolynomialRing(ZZ)
g_zz = g_int(x_var=x, y_var=y)

# Hàm tìm nghiệm nhỏ được đơn giản hóa và đáng tin cậy hơn
def find_small_roots(f, X, Y, m=2, d=None):
    if not d:
        d = f.degree()

    N = f.base_ring().order()
    P.<x,y> = f.parent()

    # 1. Tạo các đa thức dịch chuyển (shift polynomials)
    shifts = []
    for i in range(m + 1):
        for j in range(m - i + 1):
            shifts.append(x**i * y**j * f**j * N**(m-j))

    # 2. Xây dựng ma trận
    # Cơ sở đơn thức là tất cả x^a * y^b với a+b <= d*m
    monomials = [x**a * y**b for a in range(d*m+1) for b in range(d*m+1) if a+b <= d*m]
    
    dim = len(shifts)
    M = Matrix(ZZ, dim, len(monomials))
    
    for i in range(dim):
        for j in range(len(monomials)):
            M[i,j] = shifts[i].coefficient(monomials[j]) * X**monomials[j].degree(x) * Y**monomials[j].degree(y)

    B = M.LLL()

    # 3. Tái tạo đa thức
    P_QQ.<u,v> = PolynomialRing(QQ)
    new_polys = []
    
    for row in B:
        p = 0
        for i in range(len(monomials)):
            p += QQ(row[i]) / (X**monomials[i].degree(x) * Y**monomials[i].degree(y)) * u**monomials[i].degree(x) * v**monomials[i].degree(y)
        
        if p != 0:
            new_polys.append(p)
    
    # 4. Tìm nghiệm chung
    try:
        I = Ideal(new_polys)
        variety = I.variety()
        roots = []
        for r in variety:
            roots.append((ZZ(r[u]), ZZ(r[v])))
        return roots
    except Exception as e:
        print(f"[-] Lỗi khi tìm nghiệm chung: {e}")
        return []

print("[+] Bước 3: Tìm nghiệm nhỏ... (Quá trình này có thể mất vài phút)")
g_mod_n = g_zz.change_ring(Zmod(n))
roots = find_small_roots(g_mod_n, X=K, Y=K)

if not roots:
    print("[-] Không tìm thấy nghiệm. Hãy thử chạy lại script get_ciphertexts.py để lấy dữ liệu mới.")
else:
    r1_sol, r2_sol = roots[0]
    print(f"[+] Tìm thấy nghiệm: r1 = {r1_sol}, r2 = {r2_sol}")

    print("[+] Bước 4: Khôi phục tin nhắn gốc m1...")
    s = (r2_sol - r1_sol) % n
    
    try:
        t = pow(s, 3, n)
        numerator = c2 + 2*c1 - t
        denominator = 3 * (c2 - c1 + 2*t)
        
        m1 = (s * numerator * inverse(int(denominator), int(n))) % n

        assert pow(m1, 3, n) == c1
        assert pow(m1 + s, 3, n) == c2
        print(f"[+] Khôi phục thành công m1 = {m1}")

        print("[+] Bước 5: Lấy flag...")
        F_base = m1 - r1_sol
        flag_long = F_base >> 256
        flag = long_to_bytes(int(flag_long))
        
        print("\n" + "="*40)
        print(f"[SUCCESS] Flag: {flag.decode()}")
        print("="*40)

    except (ValueError, ZeroDivisionError):
        print("[-] Lỗi: Không thể tìm nghịch đảo modular. Dữ liệu có thể không hợp lệ. Hãy thử lại với dữ liệu mới.")