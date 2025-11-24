#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Auto-deobfuscate LITCTF "jailpy3" -> extract final flag
#
# Steps:
# 1) Replace .select.POLL* tails by their names and safely eval chr(<expr>) where <expr>
#    is made of integers, + - * // % ^ | & ( ) and POLL* constants.
# 2) Merge adjacent string literals created by chr() expansion.
# 3) Repeat until no more chr().
# 4) Parse the resulting print(...) that embeds: types.FunctionType(marshal.loads(bytes.fromhex(...)), {...})()
#    - extract the hex blob, run only that code object (types.FunctionType) in a tiny sandbox
#    - collect prefix/suffix around it
# 5) Print full flag.

import re
import ast
import marshal
import types

# --- config ---
INPUT_FILE = "code.py"   # path tới file đề gốc
MAX_ROUNDS = 40          # đủ lớn để “bóc” nhiều lớp
VERBOSE = True

# --- small helpers ---

def dbg(*a):
    if VERBOSE:
        print(*a)

# Các hằng POLL* thường gặp; nhiều obfuscator dùng để tạo bitmask nhỏ 1,2,4,8,16,32,64...
# Lấy giá trị đúng từ Python để eval biểu thức chr() một cách an toàn mà không cần import file gốc.
try:
    import select as _sel
    POLL_CONSTS = {
        "POLLIN": _sel.POLLIN,
        "POLLPRI": _sel.POLLPRI,
        "POLLOUT": _sel.POLLOUT,
        "POLLERR": _sel.POLLERR,
        "POLLHUP": _sel.POLLHUP,
        "POLLNVAL": _sel.POLLNVAL,
        "POLLRDNORM": getattr(_sel, "POLLRDNORM", 0),
    }
except Exception:
    # fallback: giá trị phổ biến trên Linux (không tuyệt đối nhưng đủ cho đề này)
    POLL_CONSTS = {
        "POLLIN": 1,
        "POLLPRI": 2,
        "POLLOUT": 4,
        "POLLERR": 8,
        "POLLHUP": 16,
        "POLLNVAL": 32,
        "POLLRDNORM": 64,
    }

# Trong chr(...) họ hay viết ... .select.POLLIN ^ ... .select.POLLPRI ...
# Ta không cần biết phần trước; chỉ cần biến tail ".select.POLLXXX" -> "POLLXXX"
SELECT_TAIL_RE = re.compile(r"\.select\.(POLL[A-Z_]+)")

# bắt từng chr(expr)
CHR_CALL_RE = re.compile(r"chr\s*\(\s*(?P<expr>[^()]+?)\s*\)")

# một số lớp noise dễ thấy (không bắt buộc nhưng giúp co ngắn sớm)
NOISE_REPLACEMENTS = [
    # rút gọn các truy cập .__builtins__[ ... ](...) .select.POLL* -> giữ lại .select.POLL*
    (re.compile(r"__builtins__\s*\[[^\]]+\]\s*\([^)]+\)"), "X"),  # giữ chỗ
    (re.compile(r"\{\}\.__class__\.__subclasses__\(\)\[\d+\]\.\w+"), "X"),
]

# gộp "abc" + "def" -> "abcdef" bằng AST literal_eval an toàn
def fold_string_additions(code: str) -> str:
    """
    Tìm các biểu thức chuỗi cộng chuỗi ở mức literal và gộp lại.
    Làm theo kiểu đơn giản: tìm "...' + '..." ở ngoài khối code; lặp đến khi hết.
    """
    # Cho chắc chắn, dùng regex để gộp các cụm cơ bản trước.
    # Lặp một số vòng để co tối đa.
    STR_ADD_RE = re.compile(r"(?P<q1>['\"])(?P<a>(?:\\.|[^\\])*?)\1\s*\+\s*(?P<q2>['\"])(?P<b>(?:\\.|[^\\])*?)\3")
    for _ in range(12):
        new_code = STR_ADD_RE.sub(lambda m: repr(
            bytes(m.group('a'), 'utf-8').decode('unicode_escape') +
            bytes(m.group('b'), 'utf-8').decode('unicode_escape')
        ), code)
        if new_code == code:
            break
        code = new_code
    return code

def safe_eval_int_expr(expr: str) -> int:
    """
    Đánh giá biểu thức số học an toàn cho đối số của chr().
    Hỗ trợ: + - * // % ^ | & ( ) và các tên POLL* đã map sẵn.
    """
    # Thay mọi ".select.POLLXXX" -> "POLLXXX"
    expr = SELECT_TAIL_RE.sub(lambda m: m.group(1), expr)
    # Chặn tên lạ: chỉ cho chữ số, toán tử, khoảng trắng, ngoặc, và A-Z_ (cho POLL*)
    if not re.fullmatch(r"[0-9\s\+\-\*\/\%\^\|\&\(\)A-Z_]+", expr):
        # Thử làm sạch noise đã thay bằng "X"
        expr_clean = expr.replace("X", "")
        if not re.fullmatch(r"[0-9\s\+\-\*\/\%\^\|\&\(\)A-Z_]+", expr_clean):
            raise ValueError(f"Unexpected tokens in chr() expr: {expr!r}")
        expr = expr_clean

    env = {"__builtins__": None}
    env.update(POLL_CONSTS)
    return eval(expr, env, {})

def replace_chr_calls_once(s: str) -> str:
    changed = False
    def repl(m):
        nonlocal changed
        expr = m.group('expr')
        val = safe_eval_int_expr(expr)
        changed = True
        try:
            return repr(chr(val))  # thành literal chuỗi: 'A'
        except ValueError:
            # Nếu val ngoài BMP, cứ để nguyên để không hỏng
            return f"chr({val})"

    out = CHR_CALL_RE.sub(repl, s)
    return out, changed

HEX_MARSHAL_RE = re.compile(
    r"bytes\.fromhex\(\s*['\"](?P<hex>[0-9a-fA-F]+)['\"]\s*\)"
)

def extract_prefix_hex_suffix(final_code: str):
    """
    Cố gắng tìm print( <prefix_str> + types.FunctionType(marshal.loads(bytes.fromhex('HEX')), {...})() + <suffix_str> )
    bằng AST, để chắc ăn trong điều kiện spacing khác nhau.
    """
    tree = ast.parse(final_code)

    class Finder(ast.NodeVisitor):
        def __init__(self):
            self.result = None

        def visit_Call(self, node: ast.Call):
            # Tìm print(...)
            is_print = isinstance(node.func, ast.Name) and node.func.id == "print"
            if is_print and node.args:
                # reconstruct chuỗi bằng cách duyệt BinOp Add
                try:
                    piece_prefix, hexblob, piece_suffix = self._extract_from_expr(node.args[0])
                    if hexblob:
                        self.result = (piece_prefix, hexblob, piece_suffix)
                        return
                except Exception:
                    pass
            self.generic_visit(node)

        def _extract_from_expr(self, node):
            # Kỳ vọng dạng prefix + FunctionType(...)() + suffix
            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
                left = node.left
                right = node.right
                L = self._extract_from_expr(left)
                R = self._extract_from_expr(right)
                # cases:
                # (prefix, hex, None) + (None, None, suffix)  -> merge
                if L[1] and R[1]:
                    # Hai hex? Không phải case này
                    return ("", None, "")
                if L[1]:
                    # L có hex, R là suffix string
                    return (L[0], L[1], (R[0] if R[0] else R[2]))
                if R[1]:
                    # R có hex, L là prefix string
                    return ((L[2] if L[2] else L[0]), R[1], R[2])
                # cả hai đều là string thuần -> ghép
                return ((L[0] or L[2] or "") + (R[0] or R[2] or ""), None, "")

            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                return (node.value, None, None)

            # Tìm FunctionType(marshal.loads(bytes.fromhex('...')), {...})()
            if isinstance(node, ast.Call):
                # Có thể là (... )() bọc ngoài
                inner = node.func if isinstance(node.func, ast.Call) else node
                hexblob = self._find_hex_in_call(inner)
                if hexblob:
                    return ("", hexblob, "")
            return ("", None, "")

        def _find_hex_in_call(self, call_node: ast.Call):
            # Kiểm tra call của loại types.FunctionType(marshal.loads(bytes.fromhex('HEX')), {...})
            # => tìm bytes.fromhex('HEX') ở bất kỳ arg/kwarg
            for sub in ast.walk(call_node):
                if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute):
                    if sub.func.attr == "fromhex" and isinstance(sub.func.value, ast.Name) and sub.func.value.id == "bytes":
                        if sub.args and isinstance(sub.args[0], ast.Constant) and isinstance(sub.args[0].value, str):
                            return sub.args[0].value
            return None

    f = Finder()
    f.visit(tree)
    return f.result  # (prefix, hexblob, suffix) hoặc None

def run_hex_codeobject(hexblob: str) -> str:
    """
    Tạo code object từ marshal.loads(bytes.fromhex(...)) rồi chạy bằng FunctionType trong sandbox.
    Sandbox ở đây chỉ cần cung cấp 'os' (như bài mẫu) – nếu code object dùng 'os'.
    """
    co = marshal.loads(bytes.fromhex(hexblob))
    # Môi trường hạn chế – chỉ thứ họ mong muốn trong đề (os)
    import os
    g = {'os': os}
    res = types.FunctionType(co, g)()
    if not isinstance(res, str):
        res = str(res)
    return res

def main():
    src = open(INPUT_FILE, "rb").read().decode("utf-8", "ignore")
    dbg("[start] size =", len(src))

    prev = None
    for round_idx in range(1, MAX_ROUNDS + 1):
        s = src

        # rút gọn noise dễ thấy để các regex chr(...) hoạt động dễ hơn
        for pat, rep in NOISE_REPLACEMENTS:
            s = pat.sub(rep, s)

        # thay tail ".select.POLLXXX" -> "POLLXXX"
        s = SELECT_TAIL_RE.sub(lambda m: m.group(1), s)

        # thay các chr(...) thành literal
        s, changed = replace_chr_calls_once(s)

        # gộp chuỗi
        s = fold_string_additions(s)

        # nếu không còn thay đổi đáng kể, dừng
        if prev is not None and s == prev:
            dbg(f"[round {round_idx}] no further change; stop.")
            src = s
            break

        dbg(f"[round {round_idx}] size {len(src)} -> {len(s)}")
        prev = src
        src = s

    # Đến đây ta kỳ vọng đã có print với marshal.loads(bytes.fromhex(...))
    found = extract_prefix_hex_suffix(src)
    if not found:
        # fallback: bóc thẳng hex
        m = HEX_MARSHAL_RE.search(src)
        if not m:
            print("\n[!] Could not find marshal hex blob. Dump preview:\n")
            print(src[:5000])
            return
        hexblob = m.group("hex")
        prefix = ""
        suffix = ""
    else:
        prefix, hexblob, suffix = found

    middle = run_hex_codeobject(hexblob)
    flag = f"{prefix}{middle}{suffix}"

    print("\n== FLAG ==")
    print(flag)

if __name__ == "__main__":
    main()
