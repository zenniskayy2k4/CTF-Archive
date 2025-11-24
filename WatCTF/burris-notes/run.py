# Focused run on key lengths 7..10 (recommended). More intensive but limited to finish quickly.
# Steps (for each keylen):
#  - optimize 36-alphabet Vigenere key (several restarts, simulated annealing)
#  - for best dec36 candidate run substitution hillclimb (quadgram scoring)
#  - collect top results
import math, random, string, collections, time, os
random.seed(1337)

# load quadgrams
quadfile = "english_quadgrams.txt"
quadgrams = {}
total = 0
with open(quadfile, "r", encoding="utf-8", errors="ignore") as f:
    for line in f:
        line=line.strip()
        if not line: continue
        parts = line.split()
        if len(parts)==2 and parts[0].isalpha():
            quadgrams[parts[0].lower()] = int(parts[1])
            total += int(parts[1])
logp = {q: math.log10(c/total) for q,c in quadgrams.items()}
floor = math.log10(0.01/total)

def quadgram_score(text):
    T = ''.join([c for c in text.lower() if c.isalpha()])
    if len(T) < 4: return -1e9
    s=0.0
    for i in range(len(T)-3):
        s += logp.get(T[i:i+4], floor)
    return s

alpha36 = string.ascii_lowercase + "0123456789"
idx36 = {ch:i for i,ch in enumerate(alpha36)}
cipher = "vtipupltzmyb3gn11yow303h3aigimf$ap3j3kk"
alphabet = string.ascii_lowercase

def decrypt36(cipher, key_shifts):
    out = []
    ki=0
    for ch in cipher.lower():
        if ch in idx36:
            s = key_shifts[ki % len(key_shifts)]
            cidx = idx36[ch]
            pidx = (cidx - s) % 36
            out.append(alpha36[pidx])
            ki += 1
        else:
            out.append(ch)
    return ''.join(out)

# substitution helpers
def freq_init_map(text_letters):
    freq = collections.Counter(text_letters)
    sorted_by_freq = [x[0] for x in freq.most_common()]
    common_order = list("etaoinshrdlcumwfgypbvkjxqz")
    mapping={}
    used=set()
    for i,ch in enumerate(sorted_by_freq):
        if i < len(common_order):
            mapping[ch]=common_order[i]; used.add(common_order[i])
    remaining=[c for c in alphabet if c not in used]
    random.shuffle(remaining)
    for c in alphabet:
        if c not in mapping: mapping[c]=remaining.pop()
    return mapping

def sub_hillclimb_letters_only(letters_only, restarts=80, iters=5000):
    best_over = (-1e9, None, None)  # score, plaintext, mapping
    for r in range(restarts):
        if r==0:
            mapping = freq_init_map(letters_only)
        else:
            perm = list(alphabet); random.shuffle(perm)
            mapping = {alphabet[i]:perm[i] for i in range(26)}
        cur_plain = ''.join(mapping[ch] for ch in letters_only)
        cur_score = quadgram_score(cur_plain)
        for i in range(iters):
            a,b = random.sample(alphabet,2)
            mapping[a], mapping[b] = mapping[b], mapping[a]
            cand_plain = ''.join(mapping[ch] for ch in letters_only)
            cand_score = quadgram_score(cand_plain)
            if cand_score > cur_score or math.exp((cand_score-cur_score)/0.5) > random.random():
                cur_score = cand_score; cur_plain = cand_plain
                if cur_score > best_over[0]:
                    best_over = (cur_score, cur_plain, mapping.copy())
            else:
                mapping[a], mapping[b] = mapping[b], mapping[a]
    return best_over

def optimize_key36(cipher, keylen, iterations=9000):
    seq = [c for c in cipher.lower() if c in alpha36]
    cols = [[] for _ in range(keylen)]
    for i,ch in enumerate(seq):
        cols[i%keylen].append(ch)
    init_shifts = []
    for col in cols:
        best_s=-1; best_count=-1
        for s in range(36):
            count=0
            for ch in col:
                pidx=(idx36[ch]-s)%36
                if alpha36[pidx].isalpha(): count+=1
            if count>best_count:
                best_count=count; best_s=s
        init_shifts.append(best_s if best_s!=-1 else random.randrange(36))
    key = init_shifts[:]; best_key=key[:]; best_plain=decrypt36(cipher,best_key)
    best_score=quadgram_score(''.join([c for c in best_plain if c.isalpha()]))
    cur_key=key[:]; cur_plain=best_plain; cur_score=best_score
    T0=1.0; Tend=1e-6
    for i in range(iterations):
        T = T0 * ((Tend/T0) ** (i/iterations))
        pos = random.randrange(keylen)
        old = cur_key[pos]
        cur_key[pos] = random.randrange(36)
        cand_plain = decrypt36(cipher, cur_key)
        cand_score = quadgram_score(''.join([c for c in cand_plain if c.isalpha()]))
        delta = cand_score - cur_score
        if delta>0 or math.exp(delta/max(T,1e-12))>random.random():
            cur_score=cand_score; cur_plain=cand_plain
            if cur_score>best_score:
                best_score=cur_score; best_key=cur_key.copy(); best_plain=cur_plain
        else:
            cur_key[pos]=old
    return best_score, best_key, best_plain

# main focused loop
results = []
start = time.time()
for keylen in range(7,11):
    for restart in range(6):
        iters = 12000 if restart==0 else 8000
        s36, ksh, dec36 = optimize_key36(cipher, keylen, iterations=iters)
        letters_only = ''.join([c for c in dec36 if c.isalpha()])
        if len(letters_only)>=8:
            sub_score, sub_plain, sub_map = sub_hillclimb_letters_only(letters_only, restarts=60, iters=4000)
        else:
            sub_score, sub_plain, sub_map = -1e9, "", None
        total = s36 + sub_score
        results.append((total, keylen, ksh, dec36, sub_score, sub_plain, sub_map))
        print(f"keylen={keylen} restart={restart} s36={s36:.2f} sub={sub_score:.2f} total={total:.2f} dec36_snip={dec36[:100]} sub_plain_snip={sub_plain[:100]}")
end=time.time()
print("Focused run done in", end-start, "s")

# sort and show top 6
results.sort(key=lambda x: -x[0])
top = results[:6]
for i,cand in enumerate(top,1):
    total, keylen, ksh, dec36, sub_score, sub_plain, sub_map = cand
    print("\n---- TOP", i, "total=", total, "keylen=", keylen, "key_shifts=", ksh)
    print("dec36:", dec36)
    print("sub_plain:", sub_plain)
    # try leet replacements
    def leet(s, rep): return ''.join(rep.get(ch,ch) for ch in s)
    reps = [{'3':'e','1':'i','0':'o','$':'_'}, {'3':'e','1':'l','0':'o','$':'_'}, {'3':'_','1':'_','0':'_','$':'_'}]
    for rep in reps:
        print(" rep", rep, "->", leet(dec36, rep))
    # check for watctf{
    for rep in reps:
        t = leet(dec36, rep)
        print(t)