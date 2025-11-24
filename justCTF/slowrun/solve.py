# slowrun_solver.py
# Reconstructs the value printed by ./slowrun 13337 and decodes it as big-endian ASCII.

M = int("12871709638832864416674237492708808074465131233250468097567609804146306910998417223517320307084142930385333755674444057095681119233485961920941215894136808839080569675919567597231")
C = int("805129649450289111374098215345043938348341847793365469885914570440914675704049341968773123354333661444680237475120349087680072042981825910641377252873686258216120616639500404381")

def G_mod(n: int, mod: int) -> int:
    """Compute G(n) modulo mod, per sub_12E9 + sub_1500, using DP."""
    # Base cases from sub_12E9:
    # G(0) = 2; G(n) = 1 for n <= 1 (including negatives).
    if n == 0:
        return 2 % mod
    if n <= 1:
        return 1 % mod

    # We need G(0..n); handle G(2) exactly (since H(1) = 1 base, not the general formula)
    G = [0] * (n + 1)
    G[0] = 2 % mod
    G[1] = 1 % mod

    # Direct from definition for n = 2:
    # G(2) = (2-4) + 73*2^5 + 8*2^3 + H(1), with H(1) = 1
    G[2] = ((2 - 4) + 73 * (2 ** 5) + 8 * (2 ** 3) + 1) % mod

    # For n >= 3, we can use the derived recurrence:
    # H(m) = G(m-1) + 3*G(m-2) - 5*G(m-3) + 3*m^4   (valid for m >= 2)
    # G(n) = (n-4) + 73*n^5 + 8*n^3 + H(n-1)
    #      = G(n-2) + 3*G(n-3) - 5*G(n-4) + [(n-4) + 73*n^5 + 8*n^3 + 3*(n-1)^4]
    for k in range(3, n + 1):
        poly = (k - 4) + 73 * (k ** 5) + 8 * (k ** 3) + 3 * ((k - 1) ** 4)
        # Careful: k-4 index appears when k >= 4; for k=3 treat G(-1) as 1, G(-2) as 1 per base “<=1 → 1”.
        g_km2 = G[k - 2]
        g_km3 = G[k - 3]
        g_km4 = (G[k - 4] if k - 4 >= 0 else (1 % mod))
        G[k] = (g_km2 + 3 * g_km3 - 5 * g_km4 + poly) % mod

    return G[n] % mod

def slowrun_value(n: int) -> int:
    """Emulates sub_1878 for n: returns the big decimal integer printed by the binary."""
    if n <= 100:
        g = G_mod(n, 10**100000)  # dummy large mod; for n<=100 they don't mod by M
        # But we don't need the exact huge integer here, only n=13337 path is used.
        return g
    # For n > 100: result = ((G(n) % M) normalized) + C
    g = G_mod(n, M)
    return (g % M + M) % M + C

def to_ascii_be(x: int) -> str:
    """Interpret integer as big-endian bytes and ASCII-decode."""
    blen = (x.bit_length() + 7) // 8
    data = x.to_bytes(blen, byteorder="big")
    return data.decode("ascii", errors="strict")

if __name__ == "__main__":
    n = 13337
    R = slowrun_value(n)
    print("decimal printed by binary:\n", R)
    flag = to_ascii_be(R)
    print("flag:", flag)
