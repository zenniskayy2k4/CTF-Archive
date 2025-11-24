import re, ast, sys
import itertools

# ----------- parsing -----------
def parse_out(path):
    txt = open(path, 'r').read()
    ct = Integer(re.search(r'ct\s*=\s*(\d+)', txt).group(1))
    m  = Integer(re.search(r'm\s*=\s*(\d+)', txt).group(1))
    nums = ast.literal_eval(re.search(r'nums\s*=\s*(\[.*\])', txt, re.S).group(1))
    nums = [Integer(x) for x in nums]
    e = Integer(0x10001)
    return ct, m, nums, e

# ----------- ACD via LLL -----------
def recover_one_factor_ACD(nums, m, Bbits=260, subset_size=8, tries=200):
    """
    Try to recover a nontrivial factor of m from nums via Howgrave-Graham ACD.
    nums: list of large integers; each is x = q*p + r with |r| < 2^Bbits for some prime p | m
    We repeatedly pick a random subset and run an LLL lattice to get a short combination sum u_i*y_i.
    """
    B = Integer(1) << Bbits
    n = len(nums)
    if n < subset_size+1:
        subset_size = n-1
    # precompute a reference
    for attempt in range(tries):
        # choose a random anchor and a subset for differences
        idxs = sorted(sample(range(n), subset_size+1))
        anchor = nums[idxs[0]]
        others = [nums[i] for i in idxs[1:]]
        ys = [Integer(v - anchor) for v in others]  # y_i = x_i - x_0 = (a_i)p + (e_i - e_0), |e_i - e_0| < 2^(Bbits+1)

        k = len(ys)
        # lattice dimension k+1
        # basis vectors: for i=1..k
        #   v_i has X on i-th coord and ys[i-1] on the last coord
        # plus one vector with last coord Y (very large)
        X = Integer(1) << (Bbits + 20)       # scale > error bound
        Y = X**k                              # huge to bias last coeff to 0 in short vectors

        M = Matrix(ZZ, k+1, k+1)
        for i in range(k):
            M[i, i] = X
            M[i, k] = ys[i]
        M[k, k] = Y

        # LLL
        L = M.LLL()

        # Try short vectors to produce combinations near 0
        for row in L.rows():
            coeffs = list(row)              # length k+1: (u1*X, ..., uk*X, sum(u_i*y_i) + u_{k+1}*Y)
            u = [ZZ(c // X) for c in coeffs[:k]]    # recover u_i from scaled coords
            # last coordinate (without the Y term if possible)
            # Ideally, LLL favors u_{k+1} = 0 because Y is huge, but we also try neutralizing it:
            s = sum(u[i]*ys[i] for i in range(k))
            g = gcd(m, abs(s))
            if 1 < g < m:
                return ZZ(g)
            # also try mod Y to neutralize the last coeff explicitly
            last = coeffs[k]
            # reduce last by multiples of Y (should already be small)
            last_mod = last % Y
            s2 = Integer(last_mod)
            g2 = gcd(m, abs(s2))
            if 1 < g2 < m:
                return ZZ(g2)

    return ZZ(1)

# ----------- factor m using ACD repeatedly -----------
def factor_from_nums(nums, m, target_cnt=32, Bbits=260):
    factors = []
    rem = ZZ(m)
    # Keep trying to peel off factors until done
    while rem > 1 and len(factors) < target_cnt:
        # reduce nums modulo rem to keep numbers smaller (not necessary but helps numerics)
        cur_nums = [n % rem for n in nums]
        g = recover_one_factor_ACD(cur_nums, rem, Bbits=Bbits, subset_size=8, tries=300)
        if g == 1 or g == rem:
            # if stuck, try different subset sizes
            for ss in [10, 12, 6]:
                g = recover_one_factor_ACD(cur_nums, rem, Bbits=Bbits, subset_size=ss, tries=300)
                if 1 < g < rem:
                    break
        if 1 < g < rem:
            print(f"[+] Found nontrivial factor ({g.nbits()} bits)")
            factors.append(ZZ(g))
            rem //= g
        else:
            # give up loop if couldn't find new factor
            break

    # if rem still > 1, append it
    if rem > 1:
        factors.append(ZZ(rem))
    return factors

# ----------- main -----------
def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "out.txt"
    ct, m, nums, e = parse_out(path)
    print(f"[+] Parsed: {len(nums)} samples, m has {m.nbits()} bits")

    # peel primes with ACD
    factors = factor_from_nums(nums, m, target_cnt=32, Bbits=260)

    # sanity & rebuild phi
    prod = ZZ(1)
    for p in factors: prod *= p
    if prod != m:
        print(f"[!] Warning: product of recovered factors != m (got {prod.nbits()} bits). Trying to continue anyway...")
    print(f"[+] Got {len(factors)} factors; min/max bits = {min(p.nbits() for p in factors)} / {max(p.nbits() for p in factors)}")

    phi = ZZ(1)
    for p in factors: phi *= (p - 1)
    d = inverse_mod(e, phi)
    m_plain = power_mod(ct, d, m)
    msg = Integer(m_plain).to_bytes((m_plain.nbits()+7)//8, byteorder="big")
    # print and try to extract flag
    try:
        print(msg.decode(errors="ignore"))
    except:
        print(msg)
    for tag in [b"ictf{", b"CTF{", b"flag{", b"imaginary{"]:
        i = msg.find(tag)
        if i != -1:
            j = msg.find(b"}", i+1)
            if j != -1:
                print("[+] Flag:", msg[i:j+1].decode(errors="ignore"))
                return

if __name__ == "__main__":
    main()
