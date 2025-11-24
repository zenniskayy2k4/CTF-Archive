p = 29
ints = [14,6,11]

for i in ints:
    roots = [a for a in range(p) if (a * a) % p == i]
    if roots:
        print(f"Square roots of {i} mod {p} are: {roots}")
    else:
        print(f"{i} is not a quadratic residue mod {p}")
