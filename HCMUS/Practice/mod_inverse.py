def extended_gcd(a, b):
    if b == 0:
        return (a, 1, 0)
    else:
        g, u, v = extended_gcd(b, a % b)
        return (g, v, u - (a // b) * v)

def fermat_little_theorem(a, p):
    # a^(p-1) ≡ 1 (mod p) => a^(p-2) ≡ a^(-1) (mod p)
    return pow(a, p - 2, p)

print(fermat_little_theorem(3,13))
print(fermat_little_theorem(5,17))