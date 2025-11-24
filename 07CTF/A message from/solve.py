#!/usr/bin/env python3
# solve_try_subst_from_hash.py
# Try substitution mappings derived from hash(key).
# - hash funcs: md5/sha1/sha224/sha256/sha384/sha512/blake2s/blake2b
# - two hash variants used: full hex digest, letters-only (remove digits)
# - build permutations by:
#    * seeding Python's RNG with int(digest,16) and shuffle alphabet
#    * deterministic placement using letters-only values as offsets
# - apply inverse permutation to ciphertext, then hill-climb with swaps to improve English score
# - check for 07CTF{...} and print top candidates
#
# Usage:
#   python3 solve_try_subst_from_hash.py
#   python3 solve_try_subst_from_hash.py -w my_words.txt
#
import hashlib, argparse, os, re, random, math
from collections import Counter

CIPHER = "07CYH{tkvpxgih_ajggsgsf_rfsuet}"
MAND = "CTF"
ALPH = list("abcdefghijklmnopqrstuvwxyz")
HASH_FUNCS = {
    "md5": hashlib.md5, "sha1": hashlib.sha1, "sha224": hashlib.sha224,
    "sha256": hashlib.sha256, "sha384": hashlib.sha384, "sha512": hashlib.sha512,
    "blake2s": hashlib.blake2s, "blake2b": hashlib.blake2b
}
BUILTIN_KEYS = ["key","secret","message","from","amessagefrom","a message from","crazzyman","crazzyman1081","flag","07ctf","07cyh"]

# scoring: simple quadgram-lite / freq-ish
QUADS = None
def score_text(pt):
    tl = pt.lower()
    cnt = Counter([c for c in tl if c.isalpha() or c=='_'])
    L = max(1, sum(cnt.values()))
    # letter-frequency similarity
    freqs = {'e':12.0,'t':9.1,'a':8.2,'o':7.5,'i':7.0,'n':6.7,'s':6.3,'r':6.0,'h':6.1}
    s = 0.0
    for k,v in freqs.items():
        s += v*(cnt.get(k,0)/L)
    if "ctf" in tl: s += 9.0
    if "flag" in tl: s += 6.0
    for tok in tl.split('_'):
        if tok.isalpha() and len(tok)>=3: s += 0.6*len(tok)
    return s

def letters_stream_indices(cipher):
    return [i for i,ch in enumerate(cipher) if ch.isalpha()]

def check_mand(pt):
    pos = CIPHER.find("07")
    if pos==-1: return False
    start = pos + 2
    letters=[]
    for i in range(start, len(pt)):
        if pt[i].isalpha():
            letters.append(pt[i])
            if len(letters)>=3: break
    if len(letters) < 3: return False
    return "".join(c.upper() for c in letters[:3]) == MAND

# create permutation by RNG seed from full hex digest
def perm_from_full_hex(digest_hex):
    seed = int(digest_hex, 16)
    rnd = random.Random(seed)
    perm = ALPH[:]
    rnd.shuffle(perm)
    return perm  # maps plaintext-letter -> permuted-letter (encryption). For decrypt we invert.

# create permutation deterministically from letters-only (a..f) by rotating fill
def perm_from_letters_only(letters_only, map_values='0-5'):
    # produce a permutation by placing alphabet letters into positions determined by repeated offsets
    # map a->0..f->5 or a->10..f->15 (we mod 26)
    vals = []
    for ch in letters_only:
        if 'a' <= ch <= 'f':
            base = ord(ch)-ord('a')
            if map_values == '10-15':
                v = 10 + base
            else:
                v = base
            vals.append(v)
    if not vals:
        # fallback: simple identity perm
        return ALPH[:]
    perm = [None]*26
    idx = 0
    pos = 0
    for v in vals:
        pos = (pos + v) % 26
        # find next empty slot from pos
        j = pos
        while perm[j] is not None:
            j = (j+1)%26
        perm[j] = ALPH[idx]
        idx += 1
        if idx >= 26:
            break
    # fill remaining alphabet letters in order
    for letter in ALPH[idx:]:
        # find first empty
        j = 0
        while perm[j] is not None:
            j += 1
        perm[j] = letter
    # perm now is list of plaintext letters in positions -> encryption alphabet
    # We want perm mapping plaintext->ciphertext: e.g. plaintext 'a' -> perm[0]
    return perm

def invert_perm(perm):
    # perm: list of length 26 giving mapping plaintext->cipher
    inv = {}
    for i,p in enumerate(perm):
        inv[p] = ALPH[i]
    return inv  # decrypt: cipher_letter -> plaintext_letter

def apply_subst_decrypt(cipher, inv_perm):
    out=[]
    for ch in cipher:
        if ch.isalpha():
            low = ch.lower()
            if low in inv_perm:
                dec = inv_perm[low]
                out.append(dec.upper() if ch.isupper() else dec)
            else:
                out.append('?')
        else:
            out.append(ch)
    return "".join(out)

# local hill-climb to improve mapping (swap two targets)
def hill_climb_subst(initial_inv, cipher, iterations=20000):
    # initial_inv: dict cipher->plain
    best_inv = dict(initial_inv)
    best_plain = apply_subst_decrypt(cipher, best_inv)
    best_score = score_text(best_plain)
    mapping = best_inv.copy()
    letters = ALPH[:]
    for it in range(iterations):
        # pick two plaintext letters to swap in mapping (i.e., swap images)
        a,b = random.sample(letters,2)
        # find keys (cipher letters) mapping to a and b
        ka = None; kb = None
        for k,v in mapping.items():
            if v==a: ka=k
            if v==b: kb=k
        if not ka or not kb:
            continue
        # swap
        mapping[ka], mapping[kb] = mapping[kb], mapping[ka]
        cand_plain = apply_subst_decrypt(cipher, mapping)
        sc = score_text(cand_plain)
        if sc >= best_score:
            best_score = sc
            best_plain = cand_plain
            best_inv = mapping.copy()
            # keep swap
        else:
            # revert
            mapping[ka], mapping[kb] = mapping[kb], mapping[ka]
    return best_score, best_plain, best_inv

def try_hash_and_build_perms(base_key, hf_name, hf_func, results, try_map_values=True):
    digest = hf_func(base_key.encode()).hexdigest()
    letters_only = re.sub(r"\d","",digest)
    # 1) perm from full hex seed
    perm1 = perm_from_full_hex(digest)   # encryption perm
    inv1 = invert_perm(perm1)
    dec1 = apply_subst_decrypt(CIPHER, inv1)
    sc1 = score_text(dec1)
    if check_mand(dec1):
        results.append((sc1, hf_name, base_key, "seed_fullhex", dec1))
    # hill-climb refine
    sc_h, plain_h, inv_h = hill_climb_subst(inv1, CIPHER, iterations=5000)
    if check_mand(plain_h) or sc_h > sc1 + 5:
        results.append((sc_h, hf_name, base_key, "seed_fullhex_hill", plain_h))
    # 2) perm from letters-only, map a->0..5
    for mapvals in ( '0-5', '10-15' ) if try_map_values else ('0-5',):
        perm2 = perm_from_letters_only(letters_only, map_values=mapvals)
        inv2 = invert_perm(perm2)
        dec2 = apply_subst_decrypt(CIPHER, inv2)
        sc2 = score_text(dec2)
        if check_mand(dec2):
            results.append((sc2, hf_name, base_key, f"lettersonly_{mapvals}", dec2))
        sc_h2, plain_h2, inv_h2 = hill_climb_subst(inv2, CIPHER, iterations=5000)
        if check_mand(plain_h2) or sc_h2 > sc2 + 5:
            results.append((sc_h2, hf_name, base_key, f"lettersonly_{mapvals}_hill", plain_h2))
    return

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-w','--wordlist', help='wordlist file', default=None)
    parser.add_argument('-t','--top', help='top results to show', type=int, default=20)
    args = parser.parse_args()

    base_keys = BUILTIN_KEYS[:]
    if args.wordlist and os.path.exists(args.wordlist):
        with open(args.wordlist, 'r', encoding='utf-8', errors='ignore') as f:
            base_keys = [l.strip() for l in f if l.strip()]

    results=[]
    for hf_name,hf in HASH_FUNCS.items():
        for bk in base_keys:
            try:
                try_hash_and_build_perms(bk, hf_name, hf, results)
            except Exception as e:
                # keep going
                print("err", hf_name, bk, e)
    results.sort(reverse=True, key=lambda x: x[0])
    if not results:
        print("No substitution candidates matched mandatory mapping.")
        return
    print("Top results (score, hash, base_key, mode, plaintext):")
    for rec in results[:args.top]:
        print(f"score={rec[0]:.3f} | hash={rec[1]:8s} | base='{rec[2]}' | mode={rec[3]:20s}")
        print(" plaintext:", rec[4])
        m = re.search(r"07CTF\{([^}]*)\}", rec[4])
        if m:
            print(" SUGGESTED FLAG: 07CTF{" + m.group(1) + "}")
        print("-"*70)

if __name__ == "__main__":
    main()
