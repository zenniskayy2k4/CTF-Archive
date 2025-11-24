import sys
import itertools

CIPHER_PATH = 'flag.enc'
PRINTABLE_MIN = 32
PRINTABLE_MAX = 126
FLAG_PREFIX = "v1t{"
MAX_COMBINATIONS = 200_000

def load_cipher(path=CIPHER_PATH):
    with open(path, 'r', encoding='utf-8') as f:
        return [int(x) for x in f.read().strip().split() if x.strip()]

def candidates_for_residue(r, k):
    c = []
    n = 0
    while True:
        val = r + n * k
        if val > PRINTABLE_MAX:
            break
        if val >= PRINTABLE_MIN:
            c.append(chr(val))
        n += 1
    return c

def decode_with_key(nums, k):
    lists = [candidates_for_residue(r, k) for r in nums]
    if any(len(lst) == 0 for lst in lists):
        print("Some residues have no printable candidates for k =", k); return
    total = 1
    for lst in lists:
        total *= len(lst)
        if total > MAX_COMBINATIONS:
            print("Search space too large:", total); return

    # if unique per position
    if all(len(lst) == 1 for lst in lists):
        pt = ''.join(lst[0] for lst in lists)
        print(f"Key {k} -> {pt}")
        return

    # enumerate combinations and filter by flag format
    for prod in itertools.product(*lists):
        pt = ''.join(prod)
        if pt.startswith(FLAG_PREFIX) and '}' in pt:
            print(f"Key {k} -> {pt}")

if __name__ == "__main__":
    k = int(sys.argv[1]) if len(sys.argv) > 1 else 51
    nums = load_cipher()
    decode_with_key(nums, k)