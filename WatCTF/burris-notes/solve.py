# save as solve_burris.py and run: python solve_burris.py
import re
from collections import Counter, defaultdict
from math import gcd
cipher = "vzyyrpf1zazz0piphoedxpvt2fu9i518$9_9f_php_vr"

# keep letters-only (lowercase) for Kasiski/IC/frequency analysis
letters = ''.join([c for c in cipher.lower() if c.isalpha()])

EN_FREQ = {
 'a':8.167,'b':1.492,'c':2.782,'d':4.253,'e':12.702,'f':2.228,'g':2.015,'h':6.094,
 'i':6.966,'j':0.153,'k':0.772,'l':4.025,'m':2.406,'n':6.749,'o':7.507,'p':1.929,
 'q':0.095,'r':5.987,'s':6.327,'t':9.056,'u':2.758,'v':0.978,'w':2.360,'x':0.150,
 'y':1.974,'z':0.074
}

# ---------- utilities ----------
def vigenere_decrypt_full(text, key):
    out=[]
    kidx=0
    key = key.lower()
    for ch in text:
        if ch.isalpha():
            shift = ord(key[kidx % len(key)]) - ord('a')
            val = (ord(ch.lower()) - ord('a') - shift) % 26
            out.append(chr(val + ord('a')))
            kidx += 1
        else:
            out.append(ch)
    return ''.join(out)

def vigenere_autokey_decrypt_full(text, keyprefix):
    out=[]
    key = list(keyprefix.lower())
    kidx=0
    for ch in text:
        if ch.isalpha():
            shift = ord(key[kidx]) - ord('a')
            val = (ord(ch.lower()) - ord('a') - shift) % 26
            p = chr(val + ord('a'))
            out.append(p)
            key.append(p)
            kidx += 1
        else:
            out.append(ch)
    return ''.join(out)

def caesar_shift(text, s):
    out=[]
    for ch in text:
        if ch.isalpha():
            base = 'a' if ch.islower() else 'A'
            out.append(chr((ord(ch.lower()) - ord('a') + s) % 26 + ord('a')))
        else:
            out.append(ch)
    return ''.join(out)

def index_of_coincidence(t):
    N = len(t)
    if N <= 1: return 0.0
    freqs = Counter(t)
    s = sum(v*(v-1) for v in freqs.values())
    return s / (N*(N-1))

# ---------- Kasiski (find repeated n-grams, distances) ----------
def kasiski(letters, min_len=3, max_len=6):
    repeats = defaultdict(list)
    L = len(letters)
    for n in range(min_len, max_len+1):
        seen = {}
        for i in range(L-n+1):
            seq = letters[i:i+n]
            if seq in seen:
                repeats[seq].append(i - seen[seq])
                # update first seen to earliest index is fine
            else:
                seen[seq] = i
    # aggregate gcds of distances for repeated sequences
    gcd_counts = Counter()
    for seq, dists in repeats.items():
        if not dists: continue
        g = dists[0]
        for d in dists[1:]:
            g = gcd(g, d)
        if g > 1:
            gcd_counts[g] += 1
    return repeats, gcd_counts

# ---------- frequency-based key recovery for a given key length ----------
def recover_key_by_freq(letters, key_len):
    key = []
    for i in range(key_len):
        group = letters[i::key_len]  # take every key_len-th letter in the letters-only stream
        if not group:
            key.append('a')
            continue
        best_k = None
        best_chi = float('inf')
        N = len(group)
        for k in range(26):  # try key letter shift k (0..25)
            # decrypt group by shift k
            dec = [chr((ord(c)-97 - k) % 26 + 97) for c in group]
            counts = Counter(dec)
            chi = 0.0
            for ch, ef in EN_FREQ.items():
                obs = counts.get(ch, 0)
                exp = ef * N / 100.0
                # avoid div0
                chi += ((obs - exp)**2) / (exp if exp>0 else 1e-9)
            if chi < best_chi:
                best_chi = chi
                best_k = k
        key.append(chr(best_k + 97))
    return ''.join(key)

# ---------- main pipeline ----------
print("Cipher:", cipher)
print("Letters-only:", letters)
print("IC (letters-only):", round(index_of_coincidence(letters), 4))

repeats, gcd_counts = kasiski(letters, 3, 6)
print("Kasiski gcd counts (likely key lengths):", gcd_counts.most_common())

# Try candidate key lengths (from gcds and a small range)
candidate_lens = [k for k,_ in gcd_counts.most_common()]
candidate_lens += [2,3,4,5,6,7,8,9,10]
candidate_lens = sorted(set([x for x in candidate_lens if x>0 and x<=20]))

found_any = False

# try frequency-derived keys for each candidate length
for L in candidate_lens:
    key = recover_key_by_freq(letters, L)
    pt = vigenere_decrypt_full(cipher, key)
    # try Caesar shifts on pt
    for s in range(26):
        cand = caesar_shift(pt, s)
        if "watctf{" in cand:
            print("FOUND (derived-key): key_len", L, "derived_key", key, "caesar", s)
            print(cand)
            found_any = True

# try some plausible literal keys from puzzle
plausible_keys = ["rotating","transformations","burris","burrisnotes","rotor","php","drburris","notes","rotatingalphabets","transform"]
for k in plausible_keys:
    pt = vigenere_decrypt_full(cipher, k)
    for s in range(26):
        cand = caesar_shift(pt, s)
        if "watctf{" in cand:
            print("FOUND (plausible-key):", k, "caesar", s)
            print(cand)
            found_any = True

# try autokey with plausible prefixes
for prefix in ["rotating","burris","rot","drb","transform"]:
    pt = vigenere_autokey_decrypt_full(cipher, prefix)
    for s in range(26):
        cand = caesar_shift(pt, s)
        if "watctf{" in cand:
            print("FOUND (autokey): prefix", prefix, "caesar", s)
            print(cand)
            found_any = True

if not found_any:
    print("No candidate containing 'watctf{' found automatically. Try extending wordlist or examine highest-scoring outputs manually.")
