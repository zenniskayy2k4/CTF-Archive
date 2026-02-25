import re
from dataclasses import dataclass
from typing import Dict, List, Tuple, Optional

from z3 import Bool, BoolVal, Solver, And, Or, Not, Xor, is_true, sat


# =========================================================
# CẤU HÌNH
# =========================================================
INPUT_LEN = 1279  # 0x4ff
BASE_ADDR = 0x115060


def parse_permutation_dump_robust(filename: str) -> List[int]:
    """Đọc dump Ghidra để lấy mảng hoán vị 320 dword little-endian từ DAT_00113080."""
    all_hex_bytes: List[int] = []
    with open(filename, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            # match dòng có địa chỉ 8 hex, có thể có khoảng trắng đầu dòng
            m = re.match(r"^\s*[0-9a-fA-F]{8}\s+(.*)$", line)
            if not m:
                continue
            rest = m.group(1)
            # lấy các token đúng dạng 2 hex (27, 01, 00, 00, ...)
            for tok in rest.split():
                if re.fullmatch(r"[0-9a-fA-F]{2}", tok):
                    all_hex_bytes.append(int(tok, 16))

    # DAT_00113080 là mảng dword: 320 phần tử => 1280 bytes
    indices: List[int] = []
    for i in range(0, min(len(all_hex_bytes), 320 * 4), 4):
        if i + 3 >= len(all_hex_bytes):
            break
        val = (
            all_hex_bytes[i]
            | (all_hex_bytes[i + 1] << 8)
            | (all_hex_bytes[i + 2] << 16)
            | (all_hex_bytes[i + 3] << 24)
        )
        indices.append(val)
    return indices[:320]


@dataclass(frozen=True)
class Value:
    # bytes LSB-only, little-endian: bytes[0] = low byte bit0
    bytes: List

    def size(self) -> int:
        return len(self.bytes)

    def to_size(self, size: int):
        if size <= 0:
            return Value([])
        if len(self.bytes) == size:
            return self
        if len(self.bytes) > size:
            return Value(self.bytes[:size])
        return Value(self.bytes + [BoolVal(False)] * (size - len(self.bytes)))


def _default_size_for_name(name: str) -> int:
    if name.startswith("local_"):
        return 4
    if name.startswith("uVar"):
        return 4
    if name.startswith("bVar"):
        return 1
    if "DAT_" in name:
        return 1
    return 4


def v_zero(size: int) -> Value:
    return Value([BoolVal(False)] * size)


def v_const(n: int) -> Value:
    # choose minimal size up to 4 bytes
    if n < 0:
        # treat negative as 32-bit two's complement constant (only bit0 matters per byte)
        n &= 0xFFFFFFFF
    size = max(1, min(4, (n.bit_length() + 7) // 8))
    out = []
    for i in range(size):
        out.append(BoolVal(((n >> (8 * i)) & 1) == 1))
    return Value(out)


def v_not(a: Value) -> Value:
    return Value([Not(x) for x in a.bytes])


def v_bin(a: Value, b: Value, op) -> Value:
    size = max(a.size(), b.size())
    aa = a.to_size(size).bytes
    bb = b.to_size(size).bytes
    return Value([op(aa[i], bb[i]) for i in range(size)])


def v_and(a: Value, b: Value) -> Value:
    return v_bin(a, b, And)


def v_or(a: Value, b: Value) -> Value:
    return v_bin(a, b, Or)


def v_xor(a: Value, b: Value) -> Value:
    return v_bin(a, b, Xor)


def v_shl(a: Value, shift_bits: int) -> Value:
    if shift_bits % 8 != 0:
        raise ValueError(f"Unsupported shift {shift_bits} (not multiple of 8)")
    n = shift_bits // 8
    size = a.size()
    if n >= size:
        return v_zero(size)
    # left shift by n bytes: insert zeros in low bytes
    return Value([BoolVal(False)] * n + a.bytes[: size - n])


def v_shr(a: Value, shift_bits: int) -> Value:
    if shift_bits % 8 != 0:
        raise ValueError(f"Unsupported shift {shift_bits} (not multiple of 8)")
    n = shift_bits // 8
    size = a.size()
    if n >= size:
        return v_zero(size)
    # right shift by n bytes: drop low bytes
    return Value(a.bytes[n:] + [BoolVal(False)] * n)


def v_extract(a: Value, offset: int, size: int) -> Value:
    if size <= 0:
        return Value([])
    src = a.to_size(max(a.size(), offset + size)).bytes
    return Value(src[offset : offset + size])


def v_concat(high: Value, low: Value, high_size: int, low_size: int) -> Value:
    hh = high.to_size(high_size)
    ll = low.to_size(low_size)
    # Ghidra CONCATab(high, low): low bytes first in little-endian
    return Value(ll.bytes[:low_size] + hh.bytes[:high_size])


CAST_SIZES = {
    "byte": 1,
    "undefined1": 1,
    "char": 1,
    "uchar": 1,
    "ushort": 2,
    "undefined2": 2,
    "uint3": 3,
    "int3": 3,
    "undefined3": 3,
    "uint": 4,
    "int": 4,
    "undefined4": 4,
}


def tokenize(expr: str) -> List[str]:
    tokens: List[str] = []
    i = 0
    while i < len(expr):
        c = expr[i]
        if c.isspace():
            i += 1
            continue
        if expr.startswith("<<", i) or expr.startswith(">>", i):
            tokens.append(expr[i : i + 2])
            i += 2
            continue
        if c in "()&,|^~.,":
            tokens.append(c)
            i += 1
            continue
        if c.isdigit():
            j = i
            if expr.startswith("0x", i) or expr.startswith("0X", i):
                j += 2
                while j < len(expr) and re.match(r"[0-9a-fA-F]", expr[j]):
                    j += 1
            else:
                while j < len(expr) and expr[j].isdigit():
                    j += 1
            tokens.append(expr[i:j])
            i = j
            continue
        # identifier-ish (includes _DAT_..., local_..., and slice tokens like _0_3_)
        if re.match(r"[A-Za-z_]", c):
            j = i
            while j < len(expr) and re.match(r"[A-Za-z0-9_]", expr[j]):
                j += 1
            tokens.append(expr[i:j])
            i = j
            continue

        raise ValueError(f"Unexpected char {c!r} in: {expr[i:i+40]}")
    return tokens


class Parser:
    def __init__(self, tokens: List[str], env: Dict[str, Value], bits: List):
        self.toks = tokens
        self.i = 0
        self.env = env
        self.bits = bits

    def peek(self) -> Optional[str]:
        if self.i >= len(self.toks):
            return None
        return self.toks[self.i]

    def pop(self) -> str:
        t = self.peek()
        if t is None:
            raise ValueError("Unexpected end of tokens")
        self.i += 1
        return t

    def accept(self, t: str) -> bool:
        if self.peek() == t:
            self.i += 1
            return True
        return False

    def parse(self) -> Value:
        v = self.parse_or()
        return v

    def parse_or(self) -> Value:
        v = self.parse_xor()
        while self.accept("|"):
            rhs = self.parse_xor()
            v = v_or(v, rhs)
        return v

    def parse_xor(self) -> Value:
        v = self.parse_and()
        while self.accept("^"):
            rhs = self.parse_and()
            v = v_xor(v, rhs)
        return v

    def parse_and(self) -> Value:
        v = self.parse_shift()
        while self.accept("&"):
            rhs = self.parse_shift()
            v = v_and(v, rhs)
        return v

    def parse_shift(self) -> Value:
        v = self.parse_unary()
        while True:
            op = self.peek()
            if op not in ("<<", ">>"):
                break
            self.pop()
            amt_tok = self.pop()
            if not re.fullmatch(r"(0x[0-9a-fA-F]+|\d+)", amt_tok):
                raise ValueError(f"Shift amount not constant: {amt_tok}")
            amt = int(amt_tok, 16) if amt_tok.startswith("0x") else int(amt_tok)
            v = v_shl(v, amt) if op == "<<" else v_shr(v, amt)
        return v

    def parse_unary(self) -> Value:
        if self.accept("~"):
            return v_not(self.parse_unary())

        # cast or parenthesized
        if self.accept("("):
            t = self.peek()
            if t is not None and t in CAST_SIZES:
                cast_type = self.pop()
                if not self.accept(")"):
                    raise ValueError("Bad cast syntax")
                v = self.parse_unary()
                return v.to_size(CAST_SIZES[cast_type])
            # parenthesized expr
            v = self.parse_or()
            if not self.accept(")"):
                raise ValueError("Missing ')'")
            return self.parse_postfix(v)

        return self.parse_postfix(self.parse_primary())

    def parse_postfix(self, v: Value) -> Value:
        while self.accept("."):
            sl = self.pop()
            m = re.fullmatch(r"_([0-9]+)_([0-9]+)_", sl)
            if not m:
                raise ValueError(f"Bad slice token after '.': {sl}")
            off = int(m.group(1))
            size = int(m.group(2))
            v = v_extract(v, off, size)
        return v

    def parse_primary(self) -> Value:
        t = self.pop()

        # number
        if re.fullmatch(r"0x[0-9a-fA-F]+", t) or re.fullmatch(r"\d+", t):
            n = int(t, 16) if t.startswith("0x") else int(t)
            return v_const(n)

        # function CONCATab(...)
        m = re.fullmatch(r"CONCAT([0-3])([0-3])", t)
        if m and self.accept("("):
            a = int(m.group(1))  # high bytes
            b = int(m.group(2))  # low bytes
            arg1 = self.parse_or()
            if not self.accept(","):
                raise ValueError("Missing comma in CONCAT")
            arg2 = self.parse_or()
            if not self.accept(")"):
                raise ValueError("Missing ')' in CONCAT")
            return v_concat(arg1, arg2, a, b)

        # identifier
        return self.get_ident(t)

    def get_ident(self, name: str) -> Value:
        # DAT / _DAT
        if "DAT_" in name:
            mm = re.search(r"DAT_([0-9a-fA-F]+)", name)
            if mm:
                addr = int(mm.group(1), 16)
                idx = addr - BASE_ADDR
                if 0 <= idx < INPUT_LEN:
                    return Value([self.bits[idx]])
            return Value([BoolVal(False)])

        if name in self.env:
            return self.env[name]

        # unknown -> default zero (helps with local_x used before full init)
        return v_zero(_default_size_for_name(name))


def split_top_level(expr: str, sep: str) -> List[str]:
    parts: List[str] = []
    depth = 0
    start = 0
    for i, ch in enumerate(expr):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == sep and depth == 0:
            parts.append(expr[start:i].strip())
            start = i + 1
    last = expr[start:].strip()
    if last:
        parts.append(last)
    return parts


def parse_lhs(lhs: str) -> Tuple[str, Optional[Tuple[int, int]]]:
    lhs = lhs.strip()
    # take last token (strip types)
    lhs = lhs.split()[-1]
    if "." in lhs:
        base, sl = lhs.split(".", 1)
        m = re.fullmatch(r"_([0-9]+)_([0-9]+)_", sl)
        if not m:
            return lhs, None
        return base, (int(m.group(1)), int(m.group(2)))
    return lhs, None


def solve():
    print(">>> [1/5] Khởi tạo Z3 Solver...")
    s = Solver()
    bits = [Bool(f"b_{i}") for i in range(INPUT_LEN)]

    print(">>> [2/5] Đọc constraints + dựng biểu thức (symbolic exec)...")
    with open("constraints.txt", "r", encoding="utf-8", errors="ignore") as f:
        text = f.read()

    env: Dict[str, Value] = {}
    return_expr: Optional[str] = None

    # split into statements by ';'
    for raw in text.replace("\r", "").split(";"):
        stmt = raw.strip()
        if not stmt or stmt == "}" or stmt.endswith("{"):
            continue
        if stmt.startswith("return"):
            return_expr = stmt[len("return") :].strip()
            continue
        if "=" not in stmt:
            continue

        lhs_str, rhs_str = stmt.split("=", 1)
        base, sl = parse_lhs(lhs_str)
        rhs_str = rhs_str.strip()

        # parse rhs
        tokens = tokenize(rhs_str)
        v = Parser(tokens, env, bits).parse()

        # assign
        if sl is None:
            env[base] = v
        else:
            off, size = sl
            cur = env.get(base, v_zero(_default_size_for_name(base))).to_size(4)
            vv = v.to_size(size)
            new_bytes = cur.bytes[:]
            for k in range(size):
                if off + k < len(new_bytes):
                    new_bytes[off + k] = vv.bytes[k]
            env[base] = Value(new_bytes)

    if not return_expr:
        raise RuntimeError("Không tìm thấy return expression trong constraints.txt")

    print(">>> [3/5] Thêm ràng buộc SAT từ return ...")
    # Return là chain of '&' cực dài -> split top-level '&' để add từng term byte0
    terms = split_top_level(return_expr, "&")
    added = 0
    for t in terms:
        if not t:
            continue
        tv = Parser(tokenize(t), env, bits).parse()
        if tv.size() == 0:
            continue
        s.add(tv.bytes[0])  # require bit0 of low byte == 1
        added += 1

    # Điều kiện ngoài FUN_00101289: (DAT_00115352 & 1) != 0
    idx_15352 = 0x115352 - BASE_ADDR
    if 0 <= idx_15352 < INPUT_LEN:
        s.add(bits[idx_15352])

    print(f"[+] Added constraints: {added}")

    print(">>> [4/5] Giải SAT bằng Z3 ...")
    if s.check() != sat:
        print("[-] UNSAT")
        return
    m = s.model()

    print(">>> [5/5] Giải mã flag từ hoán vị dump.txt ...")
    permutation = parse_permutation_dump_robust("dump.txt")
    if not permutation:
        print("[-] dump.txt parse fail")
        return

    # build binary input string
    binary = ["0"] * INPUT_LEN
    for i in range(INPUT_LEN):
        binary[i] = "1" if is_true(m[bits[i]]) else "0"
    binary_str = "".join(binary)

    # decode output bytes (40 bytes)
    flag_bytes = bytearray(40)
    for out_bit in range(320):
        src_idx = permutation[out_bit]
        if 0 <= src_idx < INPUT_LEN and binary_str[src_idx] == "1":
            flag_bytes[out_bit >> 3] |= 1 << (out_bit & 7)

    print("FLAG:", flag_bytes.decode("utf-8", errors="replace"))
    # nếu bạn muốn copy input để feed binary:
    # print("INPUT_1279_BITS =", binary_str)


if __name__ == "__main__":
    solve()