from __future__ import annotations
from dataclasses import dataclass
from typing import List, Tuple, Optional, Callable, Dict

from z3 import BitVec, BitVecVal, Solver, sat, unsat


EYE = "𓁹"
PUSH = "𓑀"
OP = "𓃭"
CMP = "𓈖"

# Cuneiform block is U+12000..U+123FF
CUN_BASE = 0x12000
CUN_MAX = 0x123FF


def cun_byte(ch: str) -> int:
    """
    Convert a single Cuneiform codepoint to the VM 'byte' it represents.
    Most of these challenges use: val = ord(ch) - 0x12000, then truncated to 8-bit.
    """
    o = ord(ch)
    if not (CUN_BASE <= o <= CUN_MAX):
        raise ValueError(f"Not a cuneiform codepoint: {ch} (ord={hex(o)})")
    return (o - CUN_BASE) & 0xFF


def maybe_cun_byte(tok: str) -> Optional[int]:
    if len(tok) != 1:
        return None
    o = ord(tok)
    if CUN_BASE <= o <= CUN_MAX:
        return (o - CUN_BASE) & 0xFF
    return None


def tokenize_hiero(text: str) -> List[str]:
    # Split by whitespace, keep symbols
    toks: List[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        toks.extend(line.split())
    return toks


@dataclass(frozen=True)
class Eq:
    a: int
    b: int
    c: int


def extract_equations(tokens: List[str]) -> List[Eq]:
    """
    Extract patterns like:
      𓁹 <idxA> 𓑀 𓁹 <idxB> 𓑀 𓃭 𓁹 <const> 𓈖 ...
    from the flat token stream.
    """
    eqs: List[Eq] = []

    i = 0
    n = len(tokens)
    while i < n:
        if tokens[i] != OP:
            i += 1
            continue

        # Find the pattern around OP by looking backward:
        # ... EYE idxA PUSH EYE idxB PUSH OP ...
        # We'll scan backwards up to ~8 tokens to be safe.
        a = b = None

        # We expect: [EYE, idxA, PUSH, EYE, idxB, PUSH, OP]
        # i is at OP index
        if i >= 6:
            if (
                tokens[i - 6] == EYE
                and tokens[i - 4] == PUSH   # <-- đúng: i-4 là 𓑀
                and tokens[i - 3] == EYE    # <-- đúng: i-3 là 𓁹
                and tokens[i - 1] == PUSH   # <-- đúng: i-1 là 𓑀
            ):
                idxA = maybe_cun_byte(tokens[i - 5])  # i-5
                idxB = maybe_cun_byte(tokens[i - 2])  # i-2
                if idxA is not None and idxB is not None:
                    a, b = idxA, idxB

        if a is None or b is None:
            i += 1
            continue

        # After OP we expect: EYE const CMP
        const_val = None
        if i + 3 < n and tokens[i + 1] == EYE:
            const_tok = tokens[i + 2]
            const_val = maybe_cun_byte(const_tok)
            if const_val is not None and tokens[i + 3] == CMP:
                eqs.append(Eq(a=a, b=b, c=const_val))

        i += 1

    return eqs


def solve_with_op(eqs: List[Eq], op_name: str) -> Optional[List[int]]:
    ops: Dict[str, Callable] = {
        "ADD": lambda x, y: x + y,
        "SUB": lambda x, y: x - y,
        "XOR": lambda x, y: x ^ y,
    }
    if op_name not in ops:
        raise ValueError(op_name)

    s = Solver()
    v = [BitVec(f"v{i}", 8) for i in range(256)]  # allow indexes up to 255 safely

    # Track constraints to debug unsat core
    for k, e in enumerate(eqs):
        s.assert_and_track(ops[op_name](v[e.a], v[e.b]) == BitVecVal(e.c, 8), f"c{k}_{e.a}_{e.b}_{e.c:02x}")

    r = s.check()
    if r != sat:
        if r == unsat:
            core = s.unsat_core()
            print(f"[-] {op_name}: UNSAT, core size={len(core)}")
            # Print a few core items to locate bad equations
            for item in core[:20]:
                print("   core:", item)
        else:
            print(f"[-] {op_name}: {r}")
        return None

    m = s.model()

    # In your original approach you cared about v6..v25
    out = []
    for i in range(6, 26):
        if m.eval(v[i], model_completion=True) is None:
            out.append(0)
        else:
            out.append(m.eval(v[i], model_completion=True).as_long() & 0xFF)
    return out


def pretty_bytes(bs: List[int]) -> str:
    s = ""
    for b in bs:
        if 32 <= b <= 126:
            s += chr(b)
        else:
            s += f"\\x{b:02x}"
    return s


def main():
    with open("challenge.hiero", "r", encoding="utf-8") as f:
        text = f.read()

    toks = tokenize_hiero(text)
    eqs = extract_equations(toks)

    print(f"[+] tokens={len(toks)}")
    print(f"[+] extracted equations={len(eqs)}")
    if not eqs:
        print("[-] Không extract được phương trình. Check pattern parser.")
        return

    # show first few eqs (sanity)
    for e in eqs[:10]:
        print(f"    eq: ({e.a}, {e.b}) ?= {e.c:#04x}")

    for op in ["ADD", "SUB", "XOR"]:
        print(f"\n=== Trying {op} ===")
        sol = solve_with_op(eqs, op)
        if sol is None:
            continue
        print(f"[+] {op}: SAT")
        print("    hex:", "".join(f"{b:02x}" for b in sol))
        print("    ascii:", pretty_bytes(sol))
        print("Flag: ", pretty_bytes(sol))
        break


if __name__ == "__main__":
    main()