p = 129403459552990578380563458675806698255602319995627987262273876063027199999999
f_list = [
    87455262955769204408909693706467098277950190590892613056321965035180446006909,
    12974562908961912291194866717212639606874236186841895510497190838007409517645,
    11783716142539985302405554361639449205645147839326353007313482278494373873961,
    55538572054380843320095276970494894739360361643073391911629387500799664701622,
    124693689608554093001160935345506274464356592648782752624438608741195842443294,
    52421364818382902628746436339763596377408277031987489475057857088827865195813,
    50724784947260982182351215897978953782056750224573008740629192419901238915128,
]
G_u = [95640493847532285274015733349271558012724241405617918614689663966283911276425, 1]
G_v = [23400917335266251424562394829509514520732985938931801439527671091919836508525]
Q_u = [
    34277069903919260496311859860543966319397387795368332332841962946806971944007,
    343503204040841221074922908076232301549085995886639625441980830955087919004,
    1,
]
Q_v = [
    102912018107558878490777762211244852581725648344091143891953689351031146217393,
    65726604025436600725921245450121844689064814125373504369631968173219177046384,
]

F = GF(p)
R.<x> = PolynomialRing(F)

def poly_from_list_constant_first(L):
    return sum(F(L[i]) * x^i for i in range(len(L)))

def mumford_key(D):
    """
    Return a hashable key for a Jacobian divisor class using its Mumford (u,v).
    Works around 'unhashable Jacobian element' for BSGS tables.
    """
    # Try common APIs across Sage versions
    try:
        u, v = D.mumford_representation()
    except Exception:
        try:
            u, v = D.mumford_rep()
        except Exception:
            # Some versions support indexing
            u, v = D[0], D[1]

    u = R(u); v = R(v)
    # serialize coefficients (constant-first)
    ku = tuple(int(c) for c in u.list())
    kv = tuple(int(c) for c in v.list())
    return (ku, kv)

def bsgs_mumford(G, Q, N):
    """
    Find k in [0, N) such that Q = k*G in additive group, using BSGS.
    Uses mumford_key() for hashing.
    """
    N = Integer(N)
    if N <= 0:
        return None

    m = ceil(sqrt(N))
    # baby steps: i*G
    table = {}
    cur = 0*G
    table[mumford_key(cur)] = Integer(0)
    for i in range(1, int(m)):
        cur = cur + G
        kcur = mumford_key(cur)
        if kcur not in table:
            table[kcur] = Integer(i)

    # giant steps: Q - j*(m*G)
    factor = -(m*G)
    cur = Q
    for j in range(0, int(m) + 1):
        kcur = mumford_key(cur)
        if kcur in table:
            i = table[kcur]
            k = i + Integer(j)*m
            if 0 <= k < N:
                return k
        cur = cur + factor
    return None

def mk_divisors(fL):
    fpoly = poly_from_list_constant_first(fL)
    C = HyperellipticCurve(fpoly)
    J = C.jacobian()

    uG = x + F(G_u[0])
    vG = R(F(G_v[0]))

    uQ = x^2 + F(Q_u[1])*x + F(Q_u[0])
    vQ = R(F(Q_v[1])*x + F(Q_v[0]))

    if ((vG^2 - fpoly) % uG) != 0: return None
    if ((vQ^2 - fpoly) % uQ) != 0: return None

    try:
        DG = J([uG, vG])
        DQ = J([uQ, vQ])
    except TypeError:
        DG = J(uG, vG)
        DQ = J(uQ, vQ)

    return (C, J, DG, DQ)

def solve_with_bsgs(DG, DQ, max_e=46, start_e=20, step=2):
    for e in range(start_e, max_e + 1, step):
        N = Integer(2)**Integer(e)
        print(f"[*] Trying custom BSGS with bound k in [0, 2^{e}) (baby ~ 2^{e//2}) ...")
        try:
            k = bsgs_mumford(DG, DQ, N)
            if k is not None:
                print("[+] Found k =", k)
                print("[+] k (int) =", int(k))
                return int(k)
        except MemoryError as ex:
            print("[!] MemoryError at e =", e, "->", ex)
            return None
        except Exception as ex:
            print("[!] BSGS failed at e =", e, "->", ex)
    return None

def attempt(fL, tag):
    print("\n====", tag, "====")
    res = mk_divisors(fL)
    if res is None:
        print("Mumford check failed for this orientation.")
        return False
    C, J, DG, DQ = res
    print("[+] Mumford checks OK")

    k = solve_with_bsgs(DG, DQ, start_e=20, max_e=46, step=2)
    if k is None:
        print("[-] No k found in tested bounds.")
        return False

    print("\nUse this k to decrypt in Python solve.py (decrypt_flag(k)).")
    return True

# Try both orientations
if attempt(f_list, "f as constant-first"):
    quit()
if attempt(list(reversed(f_list)), "f reversed"):
    quit()

print("\nNo solution found with tested BSGS bounds.")