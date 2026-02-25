import math
import random
import re
from collections import Counter
from pathlib import Path

ALPH = "abcdefghijklmnopqrstuvwxyz"
A2I = {c: i for i, c in enumerate(ALPH)}

COMMON_WORDS = {
    "a","an","and","are","as","at","be","but","by","can","do","for","from","had","has","have",
    "he","her","here","hers","him","his","how","i","if","in","into","is","it","its","just","like",
    "make","more","most","not","of","on","one","or","other","our","out","over","people","say","so",
    "some","such","take","than","that","the","their","them","then","there","these","they","this",
    "time","to","two","up","was","we","were","what","when","where","which","who","will","with","would",
    "you","your","lets","heres",
}
FLAG_LIKELY_WORDS = {
    # Helps the solver recognize the correct brace-words when it reaches them.
    "still","too","lazy","write","plaintext","so","heres","random","wikipedia","article"
}

def load_ct():
    ct_full = Path("ct.txt").read_text(encoding="utf-8", errors="ignore")
    clean = re.sub(r"[^a-zA-Z]", "", ct_full).lower()
    return ct_full, clean

def iter_corpus_texts(root: Path):
    for p in root.rglob("*.txt"):
        name = p.name.lower()
        if name in {"ct.txt", "pt.txt"}:
            continue
        try:
            if p.stat().st_size > 12_000_000:
                continue
        except OSError:
            continue
        yield p

def build_word_set(workspace_root: Path):
    counts = Counter()
    for p in iter_corpus_texts(workspace_root):
        try:
            data = p.read_text(encoding="utf-8", errors="ignore").lower()
        except OSError:
            continue
        for w in re.findall(r"[a-z]{2,}", data):
            counts[w] += 1

    # keep moderately-common words to avoid noise
    wordset = {w for w, c in counts.items() if c >= 3}
    wordset |= COMMON_WORDS
    wordset |= FLAG_LIKELY_WORDS
    return wordset

def build_quadgram_table(workspace_root: Path):
    counts = Counter()
    total = 0

    for p in iter_corpus_texts(workspace_root):
        try:
            data = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        s = re.sub(r"[^a-zA-Z]", "", data).lower()
        if len(s) < 2000:
            continue
        for i in range(len(s) - 3):
            counts[s[i:i+4]] += 1
            total += 1

    if total < 200_000:
        common = (
            "thereisandthatwithhavefromthiswillwouldwhatwhenwherewhich"
            "peopleaboutbecausecouldshouldtheirotherafterfirstthese"
            "thequickbrownfoxjumpsoverthelazydog"
        )
        s = re.sub(r"[^a-zA-Z]", "", common).lower() * 5000
        for i in range(len(s) - 3):
            counts[s[i:i+4]] += 1
            total += 1

    floor = math.log10(0.01 / total)

    # dense table for fast scoring: 26^4 = 456,976
    size = 26 ** 4
    table = [floor] * size

    def idx4(a, b, c, d):
        return (((a * 26) + b) * 26 + c) * 26 + d

    for q, c in counts.items():
        a = A2I[q[0]]
        b = A2I[q[1]]
        c2 = A2I[q[2]]
        d = A2I[q[3]]
        table[idx4(a, b, c2, d)] = math.log10(c / total)

    return table

def score_full(pt_ints, qtab):
    n = len(pt_ints)
    if n < 4:
        return -1e100
    s = 0.0
    for i in range(n - 3):
        a, b, c, d = pt_ints[i], pt_ints[i+1], pt_ints[i+2], pt_ints[i+3]
        s += qtab[(((a * 26) + b) * 26 + c) * 26 + d]
    return s

def reconstruct_full(ct_full: str, keys):
    res = []
    idx = 0
    for ch in ct_full:
        if ch.isalpha():
            s = idx % 3
            res.append(ALPH[keys[s][A2I[ch.lower()]]])
            idx += 1
        elif ch == " ":
            continue
        else:
            res.append(ch)
    return "".join(res)

def freq_seed(stream_text: str):
    order_plain = "etaoinshrdlcumwfgypbvkjxqz"
    freq = Counter(stream_text)
    cipher_sorted = [c for c, _ in freq.most_common()]
    cipher_sorted += [c for c in ALPH if c not in cipher_sorted]

    key = [None] * 26
    used_plain = set()
    for ciph, pl in zip(cipher_sorted, order_plain):
        key[A2I[ciph]] = A2I[pl]
        used_plain.add(A2I[pl])

    leftovers_plain = [i for i in range(26) if i not in used_plain]
    random.shuffle(leftovers_plain)
    for i in range(26):
        if key[i] is None:
            key[i] = leftovers_plain.pop()
    return key

def alpha_index_at(ct_full: str, pos: int) -> int:
    return sum(1 for ch in ct_full[:pos] if ch.isalpha())

def _add_constraint(constraints, ct_full, pos, plain_char):
    ch = ct_full[pos].lower()
    if not ch.isalpha():
        return
    s = alpha_index_at(ct_full, pos) % 3
    ci = A2I[ch]
    pi = A2I[plain_char]
    if ci in constraints[s] and constraints[s][ci] != pi:
        return
    constraints[s][ci] = pi

def find_crib_constraints(ct_full: str):
    constraints = [dict(), dict(), dict()]  # per stream: cipher_idx -> plain_idx

    # Crib 1: last "{", take 5 letters before it => should be "lactf"
    brace = ct_full.rfind("{")
    if brace != -1:
        letters = []
        positions = []
        i = brace - 1
        while i >= 0 and len(letters) < 5:
            if ct_full[i].isalpha():
                letters.append(ct_full[i].lower())
                positions.append(i)
            i -= 1
        letters.reverse()
        positions.reverse()
        if len(letters) == 5:
            target = "lactf"
            for ch, p, pl in zip(letters, positions, target):
                _add_constraint(constraints, ct_full, p, pl)

    # Crib 2: first 5 letters => "there"
    first_letters = []
    first_pos = []
    for i, ch in enumerate(ct_full):
        if ch.isalpha():
            first_letters.append(ch.lower())
            first_pos.append(i)
            if len(first_letters) == 5:
                break
    if len(first_letters) == 5:
        target = "there"
        for ch, p, pl in zip(first_letters, first_pos, target):
            _add_constraint(constraints, ct_full, p, pl)

    # Crib 3: "there's" -> letter right after first apostrophe is 's'
    apos = ct_full.find("'")
    if apos != -1:
        j = apos + 1
        while j < len(ct_full) and not ct_full[j].isalpha():
            j += 1
        if j < len(ct_full) and ct_full[j].isalpha():
            _add_constraint(constraints, ct_full, j, "s")

    return constraints

def init_key_with_constraints(base_key, fixed_map):
    used_plain = set(fixed_map.values())
    remaining_plain = [i for i in range(26) if i not in used_plain]
    random.shuffle(remaining_plain)

    key = [None] * 26
    for ciph, pl in fixed_map.items():
        key[ciph] = pl

    for ciph in range(26):
        if key[ciph] is not None:
            continue
        preferred = base_key[ciph]
        if preferred in remaining_plain:
            key[ciph] = preferred
            remaining_plain.remove(preferred)

    for ciph in range(26):
        if key[ciph] is None:
            key[ciph] = remaining_plain.pop()

    return key

def extract_flag(text: str):
    m = re.search(r"lactf\{[a-z_]+\}", text)
    return m.group(0) if m else None

def flag_quality(flag: str, wordset: set[str]) -> float:
    inside = flag[len("lactf{"):-1]
    parts = inside.split("_")
    if not parts:
        return 0.0
    good = sum(1 for w in parts if w in wordset)
    return good / len(parts)

def hillclimb_delta(ct_full, clean_ct, qtab, wordset, restarts=120, iters=900_000, seed=0):
    random.seed(seed)
    n = len(clean_ct)

    # Precompute positions by (stream, cipher_letter)
    pos = [[[] for _ in range(26)] for __ in range(3)]
    cipher_ints = [A2I[ch] for ch in clean_ct]
    for i, c in enumerate(cipher_ints):
        pos[i % 3][c].append(i)

    fixed = find_crib_constraints(ct_full)
    fixed_cipher = [set(m.keys()) for m in fixed]

    streams = [clean_ct[i::3] for i in range(3)]
    base_keys = [freq_seed(streams[0]), freq_seed(streams[1]), freq_seed(streams[2])]

    best_score = -1e100
    best_keys = None

    best_flag = None
    best_flag_q = 0.0

    marks = bytearray(max(0, n - 3))

    def score_at(pt, i):
        a, b, c, d = pt[i], pt[i+1], pt[i+2], pt[i+3]
        return qtab[(((a * 26) + b) * 26 + c) * 26 + d]

    for r in range(restarts):
        keys = [
            init_key_with_constraints(base_keys[0], fixed[0]),
            init_key_with_constraints(base_keys[1], fixed[1]),
            init_key_with_constraints(base_keys[2], fixed[2]),
        ]

        # Build plaintext ints
        pt = [0] * n
        for i, c in enumerate(cipher_ints):
            s = i % 3
            pt[i] = keys[s][c]

        cur_score = score_full(pt, qtab)

        T0 = 8.0
        for t in range(iters):
            T = T0 * (1.0 - (t / iters)) + 0.01

            s = random.randrange(3)
            a = random.randrange(26)
            b = random.randrange(26)
            if a == b:
                continue
            if a in fixed_cipher[s] or b in fixed_cipher[s]:
                continue

            affected_positions = pos[s][a] + pos[s][b]
            if not affected_positions:
                continue

            starts = []
            for p in affected_positions:
                lo = max(0, p - 3)
                hi = min(n - 4, p)
                for st in range(lo, hi + 1):
                    if marks[st] == 0:
                        marks[st] = 1
                        starts.append(st)

            before = 0.0
            for st in starts:
                before += score_at(pt, st)

            # swap
            keys[s][a], keys[s][b] = keys[s][b], keys[s][a]
            na = keys[s][a]
            nb = keys[s][b]
            for p in pos[s][a]:
                pt[p] = na
            for p in pos[s][b]:
                pt[p] = nb

            after = 0.0
            for st in starts:
                after += score_at(pt, st)

            delta = after - before
            accept = (delta >= 0.0) or (random.random() < math.exp(delta / T))

            if accept:
                cur_score += delta
                if cur_score > best_score:
                    best_score = cur_score
                    best_keys = [k[:] for k in keys]
            else:
                # revert
                keys[s][a], keys[s][b] = keys[s][b], keys[s][a]
                ra = keys[s][a]
                rb = keys[s][b]
                for p in pos[s][a]:
                    pt[p] = ra
                for p in pos[s][b]:
                    pt[p] = rb

            for st in starts:
                marks[st] = 0

        # report + (optional) early exit if flag is clearly good
        full = reconstruct_full(ct_full, best_keys)
        cand = extract_flag(full)
        if cand:
            q = flag_quality(cand, wordset)
            if q > best_flag_q:
                best_flag_q = q
                best_flag = cand
            print(f"[restart {r+1}/{restarts}] best_score={best_score:.2f} flag_q={best_flag_q:.2f} {best_flag}")
            if best_flag_q >= 1.0 and len(best_flag) > 30:
                return best_score, best_keys, full
        else:
            print(f"[restart {r+1}/{restarts}] best_score={best_score:.2f}")

    full = reconstruct_full(ct_full, best_keys) if best_keys else ""
    return best_score, best_keys, full

def main():
    ct_full, clean_ct = load_ct()
    workspace_root = Path(__file__).resolve().parents[1]  # LACTF/
    qtab = build_quadgram_table(workspace_root)
    wordset = build_word_set(workspace_root)

    _, best_keys, full = hillclimb_delta(
        ct_full, clean_ct, qtab, wordset,
        restarts=120,
        iters=900_000,
        seed=2
    )

    print("\n[+] Decrypted (formatted):\n")
    print(full)

    flag = extract_flag(full)
    if flag:
        print("\n[+] FLAG:", flag)
    else:
        print("\n[-] Không thấy lactf{...} trong output.")

if __name__ == "__main__":
    main()