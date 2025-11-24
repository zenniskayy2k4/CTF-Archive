import sys
sys.setrecursionlimit(2000)

from sympy import symbols, Poly, gcd
from Crypto.Util.number import long_to_bytes, inverse, isPrime

outputs = [
    1471207943545852478106618608447716459893047706734102352763789322304413594294954078951854930241394509747415,
    1598692736073482992170952603470306867921209728727115430390864029776876148087638761351349854291345381739153,
    7263027854980708582516705896838975362413360736887495919458129587084263748979742208194554859835570092536173,
    1421793811298953348672614691847135074360107904034360298926919347912881575026291936258693160494676689549954,
    7461500488401740536173753018264993398650307817555091262529778478859878439497126612121005384358955488744365,
    7993378969370214846258034508475124464164228761748258400865971489460388035990421363365750583336003815658573
]

def solve():
    print("[*] Building polynomials...")
    u = symbols('u')
    
    # P2 corresponding to i=2
    x1, x2, x3 = outputs[0], outputs[1], outputs[2]
    P2 = (x2 + u)**5 - (x1 + u)**3 * (x3 + u)**2
    
    # P3 corresponding to i=3
    x2, x3, x4 = outputs[1], outputs[2], outputs[3]
    P3 = (x3 + u)**7 - (x2 + u)**4 * (x4 + u)**3
    
    # P4 corresponding to i=4
    x3, x4, x5 = outputs[2], outputs[3], outputs[4]
    P4 = (x4 + u)**9 - (x3 + u)**5 * (x5 + u)**4

    poly2 = Poly(P2, u)
    poly3 = Poly(P3, u)
    poly4 = Poly(P4, u)

    print("[*] Calculating Resultants...")
    res23 = poly2.resultant(poly3)
    res34 = poly3.resultant(poly4)

    print("[*] Finding GCD to recover m...")
    # Resultant trả về số rất lớn, là bội của m
    m_sympy = gcd(res23, res34)
    
    m = int(m_sympy)
    
    print(f"[+] Raw GCD (bit length): {m.bit_length()}")

    # Filter out small factors (2, 3, 5...) to get the prime m
    print("[*] Finding small factors to filter out...")
    for factor in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]:
        while m % factor == 0:
            m //= factor
            
    if isPrime(m):
        print(f"[+] Found m (Prime): {m}")
    else:
        print(f"[!] WARNING: m is not prime (isPrime=False).")
        print(f"    Value of m: {m}")
        # Still try to proceed in case isPrime check is wrong or m is a special composite (though the problem states getPrime)
    print("[*] Finding u in the field Z_m...")
    
    # Convert polynomials to Z_m using set_modulus (accepts standard int)
    P2_mod = poly2.set_modulus(m)
    P3_mod = poly3.set_modulus(m)
    
    # Calculate GCD of polynomials over Z_m
    # This GCD will be linear: a*u + b
    G = gcd(P2_mod, P3_mod)
    
    if G.degree() < 1:
        print("[-] Could not find u (GCD polynomial is constant).")
        return

    # Get coefficients to solve the linear equation: coeff_1 * u + coeff_0 = 0
    coeffs = G.all_coeffs() # [coeff_1, coeff_0]
    a_coef = int(coeffs[0])
    b_coef = int(coeffs[1])
    
    # u = -b * a^-1 mod m
    u_val = (-b_coef * inverse(a_coef, m)) % m
    print(f"[+] Found u: {u_val}")

    # Recover a
    # a^2 = (x2+u)/(x1+u)
    # a^3 = (x3+u)/(x2+u)
    # a = a^3 * (a^2)^-1
    val_a2 = ((outputs[1] + u_val) * inverse(outputs[0] + u_val, m)) % m
    val_a3 = ((outputs[2] + u_val) * inverse(outputs[1] + u_val, m)) % m
    
    a_val = (val_a3 * inverse(val_a2, m)) % m
    print(f"[+] Found a: {a_val}")
    
    # Recover c
    # u = c(a-1)^-1 => c = u(a-1)
    c_val = (u_val * (a_val - 1)) % m
    print(f"[+] Found c: {c_val}")
    
    # Recover Flag
    # x1 = (a * flag + c) mod m => flag = (x1 - c) * a^-1
    flag_int = ((outputs[0] - c_val) * inverse(a_val, m)) % m
    
    try:
        flag = long_to_bytes(flag_int)
        print(f"\nFlag: {flag.decode()}")
    except Exception as e:
        print(f"\nFlag (int): {flag_int}")
        print(f"Decode error: {e}")

if __name__ == "__main__":
    solve()