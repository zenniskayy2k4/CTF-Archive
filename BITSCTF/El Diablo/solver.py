import re
import sys

RE_R0 = re.compile(r"LOAD_IMM16\s+R\[0\]\s*=\s*0x([0-9A-Fa-f]{4})")
RE_R3 = re.compile(r"LOAD_IMM16\s+R\[3\]\s*=\s*0x([0-9A-Fa-f]{4})")
RE_PRINT = re.compile(r"PRINT_FLAG_CHAR\s+R\[0\]")

def parse_pairs(asm_text: str):
    const = None
    idx = None
    pairs = []
    for line in asm_text.splitlines():
        m = RE_R0.search(line)
        if m:
            const = int(m.group(1), 16) & 0xFF
            continue
        m = RE_R3.search(line)
        if m:
            idx = int(m.group(1), 16) & 0xFFFF
            continue
        if RE_PRINT.search(line):
            if const is None or idx is None:
                raise ValueError(f"PRINT without preceding const/idx near line: {line}")
            pairs.append((const, idx))
            const, idx = None, None
    return pairs

def is_printable_flag(s: str) -> bool:
    if not s.startswith("BITSCTF{"):
        return False
    if "}" not in s:
        return False
    return all(32 <= ord(c) <= 126 for c in s)

def score_candidate(s: str) -> int:
    want = ["l4y3r", "unr4v3l", "s3cr375", "_by_", "my_"]
    score = 0
    for w in want:
        if w in s:
            score += 10

    if s.endswith("}"):
        score += 5

    bad = set("jkqvx")
    score -= sum(1 for ch in s.lower() if ch in bad)

    return score

def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "asm.txt"
    asm_text = open(path, "r", encoding="utf-8", errors="ignore").read()

    pairs = parse_pairs(asm_text)
    print(f"[+] parsed prints: {len(pairs)} chars")
    print(f"[+] unique idx: {sorted(set(i for _, i in pairs))}")

    prefix = "BITSCTF{"
    license_bytes = [None] * 10
    for pos, ch in enumerate(prefix):
        const, idx = pairs[pos]
        if idx >= 10:
            raise ValueError(f"idx too large ({idx}) at pos {pos}; expected 0..9")
        val = const ^ ord(ch)
        if license_bytes[idx] is not None and license_bytes[idx] != val:
            raise ValueError(f"conflict for license[{idx}]: {license_bytes[idx]} vs {val}")
        license_bytes[idx] = val

    unknown = [i for i, b in enumerate(license_bytes) if b is None]
    print(f"[+] known license bytes from prefix: {{i:b for i,b in enumerate(license_bytes) if b is not None}}")
    print(f"[+] unknown indices: {unknown}")

    if len(unknown) != 2:
        print("[!] warning: expected exactly 2 unknown bytes; still brute remaining ones")

    unk0, unk1 = unknown[0], unknown[1]
    best = []

    flag_re = re.compile(r"^BITSCTF\{[ -~]+\}$")

    for b0 in range(256):
        for b1 in range(256):
            tmp = license_bytes[:]
            tmp[unk0] = b0
            tmp[unk1] = b1

            out = []
            ok = True
            for const, idx in pairs:
                if idx >= 10:
                    ok = False
                    break
                out.append(chr(const ^ tmp[idx]))
            if not ok:
                continue

            s = "".join(out)
            if is_printable_flag(s) and flag_re.fullmatch(s):
                best.append((score_candidate(s), s, bytes(tmp)))

    best.sort(reverse=True, key=lambda x: x[0])

    print(f"[+] candidates (filtered): {len(best)}")
    for i, (sc, s, lic) in enumerate(best[:20]):
        print(f"\n--- ranked #{i+1} (score={sc}) ---")
        print(s)
        print("license bytes:", lic.hex())
        print("license list:", list(lic))

if __name__ == "__main__":
    main()