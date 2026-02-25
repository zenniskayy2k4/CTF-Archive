from pwn import *
from sage.all import *
from Crypto.Util.number import long_to_bytes

# CẤU HÌNH
HOST = 'challenge.cnsc.com.vn' 
PORT = 32196 

# --- CLASS HỖ TRỢ TÍNH TOÁN TRÊN CURVE ---
class CO_Solver:
    def __init__(self, p, G, O, L):
        self.Fp = GF(p)
        self.G = [self.Fp(c) for c in G]
        self.O = [self.Fp(c) for c in O]
        self.L = [self.Fp(c) for c in L]

    def intersect(self, P, Q):
        aa = P[0] - Q[0]; bb = P[1] - Q[1]; cc = P[2] - Q[2]; dd = P[3] - Q[3]
        A = aa * bb**2 + bb * cc**2 + cc * dd**2 + dd * aa**2
        C =   (P[1]**2 + 2 * P[0] * P[3]) * aa + (P[2]**2 + 2 * P[0] * P[1]) * bb \
            + (P[3]**2 + 2 * P[1] * P[2]) * cc + (P[0]**2 + 2 * P[2] * P[3]) * dd
        if A == 0: return self.O 
        t = -C / A
        return [P[0] + t * aa, P[1] + t * bb, P[2] + t * cc, P[3] + t * dd]
    
    def neg(self, P):
        if P == self.O: return P
        return self.intersect(P, self.O)

    def add(self, P, Q):
        if P == self.O: return Q
        if Q == self.O: return P
        if P == self.neg(Q): return self.O
        R = self.intersect(P, Q)
        return self.neg(R)

    def double(self, P):
        Fa = 2 * P[0] * P[3] + P[1]**2
        Fb = 2 * P[0] * P[1] + P[2]**2
        Fc = 2 * P[1] * P[2] + P[3]**2
        Fd = 2 * P[2] * P[3] + P[0]**2
        
        M_tan = Matrix(self.Fp, [[Fa, Fb, Fc, Fd], self.L])
        K = M_tan.right_kernel()
        if K.dimension() == 0: return self.O
        v = K.basis()[0]
        vx, vy, vz, vw = v

        C3 = vx * vy**2 + vy * vz**2 + vz * vw**2 + vw * vx**2
        C2 =  P[0] * (2 * vw * vx + vy**2) + P[1] * (2 * vx * vy + vz**2) \
            + P[2] * (2 * vy * vz + vw**2) + P[3] * (2 * vw * vz + vx**2)
        
        if C3 == 0: return self.O
        t = -C2 / C3
        R = [P[0] + t * vx, P[1] + t * vy, P[2] + t * vz, P[3] + t * vw]
        return self.neg(R)

    def scalarmult(self, P, k):
        R = None
        Q = P
        while k > 0:
            if k & 1:
                if R is None: R = Q
                else: R = self.add(R, Q)
            Q = self.double(Q)
            k >>= 1
        return R if R is not None else self.O

    # Baby-step Giant-step
    def bsgs(self, G, P, order):
        m = int(isqrt(order)) + 1
        baby_steps = {}
        curr = self.O
        for i in range(m):
            key = tuple(int(x) for x in curr) 
            baby_steps[key] = i
            curr = self.add(curr, G)
        
        M_pt = self.scalarmult(G, m)
        M_neg = self.neg(M_pt)
        
        curr = P
        for j in range(m):
            key = tuple(int(x) for x in curr)
            if key in baby_steps:
                return j * m + baby_steps[key]
            curr = self.add(curr, M_neg)
        return None

# --- HELPERS ---
def get_random_point_on_surface(Fp):
    while True:
        v = [Fp.random_element() for _ in range(3)]
        a = v[2]
        b = v[0]**2
        c = v[0]*v[1]**2 + v[1]*v[2]**2
        if a == 0: continue
        delta = b**2 - 4*a*c
        if is_square(delta):
            x3 = (-b + sqrt(delta)) / (2*a)
            return v + [x3]

def solve():
    # Sử dụng số nguyên tố p cố định
    p = 115792089237316195423570985008687907853269984665640564039457584007913129639747
    Fp = GF(p)
    print(f"[*] Using prime p = {p}")

    moduli = []
    remainders = []
    current_prod = 1
    target = 1 << 256

    G_vec = get_random_point_on_surface(Fp)
    O_vec = get_random_point_on_surface(Fp)

    while current_prod < target:
        try:
            r = remote(HOST, PORT, level='error')
            r.recvuntil(b"p = ")
            r.sendline(str(p).encode())
            r.recvuntil(b"G = ")
            r.sendline(",".join(map(str, G_vec)).encode())
            r.recvuntil(b"O = ")
            r.sendline(",".join(map(str, O_vec)).encode())
            
            resp = r.recvline().decode().strip()
            r.close()
            
            if "P =" not in resp: continue
            P_coords = eval(resp.split("= ")[1])
            P_vec = [Fp(c) for c in P_coords]
            
            # 1. Recover L
            M = Matrix(Fp, [G_vec, O_vec, P_vec])
            K = M.right_kernel()
            if K.dimension() < 1: continue
            L_vec = K.basis()[0]
            
            # 2. Project xuống 2D (u,v,w)
            # Chọn basis cho không gian L.x=0
            basis_matrix = matrix(L_vec).right_kernel().basis()
            R_poly = PolynomialRing(Fp, names='u,v,w')
            u, v, w = R_poly.gens()
            X_expr = [0]*4
            for i in range(4):
                X_expr[i] = basis_matrix[0][i]*u + basis_matrix[1][i]*v + basis_matrix[2][i]*w
            
            # Cubic Equation F(u,v,w) = 0
            Cubic_eq = X_expr[0]*X_expr[1]**2 + X_expr[1]*X_expr[2]**2 + \
                       X_expr[2]*X_expr[3]**2 + X_expr[3]*X_expr[0]**2
            
            # 3. Sử dụng PARI để convert sang Weierstrass form
            # Dehomogenize: w=1 -> f(u,v)
            f_affine = Cubic_eq.subs(w=1)
            
            # Gọi PARI ellfromeqn. Cần chuyển polynomial về dạng chuỗi hoặc object PARI
            try:
                # ellfromeqn trả về [a1,a2,a3,a4,a6]
                E_invs = pari(f_affine).ellfromeqn() 
            except RuntimeError:
                # Nếu PARI không tìm được Weierstrass form (do singular hoặc lỗi khác), skip
                continue
            
            # Dựng Elliptic Curve từ invariants (để tính Order)
            E = EllipticCurve(Fp, list(E_invs))
            order = E.order()
            
            # 4. Pohlig-Hellman trên Custom Curve
            solver = CO_Solver(p, G_vec, O_vec, L_vec)
            
            factors_list = list(factor(order))
            for fac, exponent in factors_list:
                q = fac ** exponent
                if q > 2**35: continue # Chỉ giải các factor nhỏ (< 35 bit)
                if any(gcd(q, m) != 1 for m in moduli): continue
                
                print(f"[+] Found factor: {q}")
                
                # P' = k * G' in subgroup
                cofactor = order // q
                G_sub = solver.scalarmult(G_vec, cofactor)
                P_sub = solver.scalarmult(P_vec, cofactor)
                
                # Nếu G_sub về 0 (G không sinh ra subgroup này), thử lại
                if G_sub == solver.O:
                    continue

                try:
                    val = solver.bsgs(G_sub, P_sub, q)
                    if val is not None:
                        remainders.append(val)
                        moduli.append(q)
                        current_prod *= q
                        print(f"[*] Solved mod {q}: {val}. Progress: {current_prod.bit_length()}/256")
                except Exception:
                    pass

        except Exception as e:
            # print(f"[!] Error: {e}")
            continue

    print("[*] Reconstructing flag...")
    k = crt(remainders, moduli)
    print(f"Flag: {long_to_bytes(k)}")

if __name__ == '__main__':
    solve()