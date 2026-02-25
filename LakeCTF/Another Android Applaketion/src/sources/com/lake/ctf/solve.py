import re
import glob
from z3 import *

def solve():
    print("--- LakeCTF Solver Final (Global Accumulation) ---")
    
    methods_db = {}
    java_files = glob.glob("*.java")
    if not java_files:
        print("Lỗi: Không tìm thấy file .java")
        return

    print(f"-> Đang đọc {len(java_files)} file...")

    # Regex patterns
    method_re = re.compile(r'static boolean Check([a-f0-9]+)\(String \w+\)\s*\{(.*?)\}', re.DOTALL)
    nop_re = re.compile(r'nop\("([a-f0-9]+)",\s*"([a-f0-9]+)"\)')
    if_re = re.compile(r'if\s*\((.*?)==\s*([-]?\d+)\)')

    # 1. Parse toàn bộ file
    for filepath in java_files:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        for m in method_re.finditer(content):
            h, body = m.groups()
            nop = nop_re.search(body)
            nxt = nop.group(1) if nop else None
            cond = if_re.search(body)
            eqn = None
            if cond:
                lhs, rhs = cond.groups()
                # Parse vế trái
                clean = lhs.replace(" ", "").replace("str.charAt", "").replace("(", "").replace(")", "")
                if clean and clean[0] not in '+-': clean = '+' + clean
                terms = [(int(i), 1 if s == '+' else -1) for s, i in re.findall(r'([\+\-])(\d+)', clean)]
                eqn = (terms, int(rhs))
            methods_db[h] = {'eqn': eqn, 'next': nxt}

    # 2. Tìm điểm bắt đầu (Roots)
    all_k = set(methods_db.keys())
    dest_k = set(v['next'] for v in methods_db.values() if v['next'])
    roots = list(all_k - dest_k)
    
    print(f"-> Tìm thấy {len(roots)} điểm bắt đầu (roots).")

    # 3. Thu thập các chuỗi hợp lệ
    valid_chains = []
    for r in roots:
        chain = []
        curr = r
        for _ in range(80):
            if curr not in methods_db: break
            chain.append(curr)
            curr = methods_db[curr]['next']
            if curr is None: break
        
        # Chỉ lấy chuỗi đủ 80 bước
        if len(chain) == 80:
            valid_chains.append(chain)

    print(f"-> Tìm thấy {len(valid_chains)} chuỗi kiểm tra độ dài 80.")

    # 4. Giải tổng hợp (Global Solve)
    # Gộp tất cả phương trình từ các chuỗi thỏa mãn "EPFL{"
    
    F = [Int(f'f{i}') for i in range(55)]
    global_solver = Solver()
    
    # Ràng buộc ký tự in được
    for x in F: global_solver.add(x >= 32, x <= 126)
    
    # Ràng buộc format flag
    global_solver.add(F[0] == 69, F[1] == 80, F[2] == 70, F[3] == 76, F[4] == 123) # EPFL{
    global_solver.add(F[54] == 125) # } (ký tự cuối cùng thường là })

    chains_used = 0
    
    for chain in valid_chains:
        # Kiểm tra thử xem chuỗi này có mâu thuẫn với EPFL{ không
        temp_s = Solver()
        temp_s.add(F[0] == 69, F[1] == 80, F[2] == 70, F[3] == 76, F[4] == 123)
        
        chain_eqs = []
        for node in chain:
            if methods_db[node]['eqn']:
                trms, val = methods_db[node]['eqn']
                expr = Sum([c * F[i] for i, c in trms])
                chain_eqs.append(expr == val)
        
        temp_s.add(chain_eqs)
        
        if temp_s.check() == sat:
            # Nếu chuỗi này hợp lệ (possible), thêm nó vào Global Solver
            global_solver.add(chain_eqs)
            chains_used += 1
    
    print(f"-> Đã gộp dữ kiện từ {chains_used} chuỗi hợp lệ.")
    
    print("-> Đang giải...")
    if global_solver.check() == sat:
        m = global_solver.model()
        flag = "".join([chr(m[F[i]].as_long()) for i in range(55)])
        print("\n" + "*"*60)
        print(f"FINAL FLAG: {flag}")
        print("*"*60 + "\n")
    else:
        print("UNSAT! Không tìm thấy nghiệm chung.")

if __name__ == "__main__":
    solve()