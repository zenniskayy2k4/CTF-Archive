import re

# 1. Đọc chal.js
with open("chal.js", "r", encoding="utf-8") as f:
    js = f.read()

# 2. Build code Python tương đương cho a..h
py_lines = []
py_lines.append("def a(): return 0")
py_lines.append("def b(x, y): return x + y")
py_lines.append("def c(x, y): return x * y")
py_lines.append("def d(x, y): return x ** y")
py_lines.append("def e(x, y): return x & y")
py_lines.append("def f(x, y, z): return y() if x else z()")
py_lines.append("def g(x, y): return ord(x[y])")
py_lines.append("def h(x): return len(x)")

# 3. Convert tất cả const A..K arrow function sang def A..K
#    Giả định tất cả ở dạng: const X = (params) => expr;
for m in re.finditer(r"const\s+([A-Z])\s*=\s*\(([^)]*)\)\s*=>\s*(.*?);", js, flags=re.DOTALL):
    name, params, expr = m.groups()
    expr_py = expr.replace("() =>", "lambda :")
    py_lines.append(f"def {name}({params}):\n    return {expr_py}")

py_code = "\n\n".join(py_lines)

# 4. Thực thi py_code để có A..K trong namespace
ns = {}
exec(py_code, ns)

# Lấy lại J để dùng sau nếu cần
J = ns["J"]

# 5. Lấy source Python của J từ py_code
start = py_code.index("def J(")
end = py_code.index("def K(", start)
J_src = py_code[start:end]

# 6. Lấy expression sau 'return ' trong def J
m = re.search(r"def J\(x\):\s*return\s*(.*)", J_src, flags=re.DOTALL)
expr_J = m.group(1).strip()

# 7. Tìm tất cả các gọi g(x, ???) trong expr_J
indices_exprs = []
idx = 0
while True:
    i = expr_J.find("g(x,", idx)
    if i == -1:
        break
    start_arg = i + len("g(x,")
    level = 0
    j = start_arg
    while j < len(expr_J):
        ch = expr_J[j]
        if ch == '(':
            level += 1
        elif ch == ')':
            if level == 0:
                break
            level -= 1
        j += 1
    arg_text = expr_J[start_arg:j].strip()
    indices_exprs.append(arg_text)
    idx = j + 1

print(f"Số lần gọi g(x, ...) trong J: {len(indices_exprs)}")

# 8. Đánh giá từng expression index (chỉ dùng các hàm a..I từ ns)
values = []
for k, arg_text in enumerate(indices_exprs):
    try:
        val = eval(arg_text, ns, {})
    except Exception as e:
        val = f"ERROR: {e}"
    values.append(val)
    print(f"{k:2d}: index expr = {arg_text}  ==>  {val}")

# 9. Tóm tắt theo thứ tự
print("\nDanh sách index dùng trong g(x, idx):")
print(values)
