# solve.py
# Yêu cầu: pip install z3-solver
# Đặt script này trong cùng thư mục với program.txt và interpreter.py

import sys

# Tăng giới hạn đệ quy để xử lý cây cú pháp rất sâu.
sys.setrecursionlimit(200000)

try:
    from interpreter import Term, App, Var, S, K, I, parse, _Const
except ImportError:
    print("Lỗi: Không tìm thấy file 'interpreter.py'.", file=sys.stderr)
    sys.exit(1)

from z3 import Solver, Bool, If, And, sat

NUM_BITS = 560
FLAG_BITS = [Bool(f'f_{i}') for i in range(NUM_BITS)]

# Sử dụng một dictionary duy nhất cho memoization
memo = {}

def translate_to_z3(term: Term):
    """
    Dịch một cách đệ quy một biểu thức SKI AST sang một biểu thức boolean Z3.
    Hàm này kết hợp cả việc rút gọn và dịch thuật.
    """
    if id(term) in memo:
        return memo[id(term)]

    # --- Trường hợp cơ sở ---
    if term is K:
        # K là TRUE
        memo[id(term)] = True
        return True

    if isinstance(term, Var):
        if term.name.startswith('_F'):
            bit_index = int(term.name[2:])
            result = FLAG_BITS[bit_index]
            memo[id(term)] = result
            return result
        raise ValueError(f"Gặp biến không xác định: {term.name}")

    # --- Trường hợp đệ quy (App) ---
    if isinstance(term, App):
        f = term.f
        x = term.x

        # Mẫu FALSE: (K I)
        if f is K and x is I:
            memo[id(term)] = False
            return False

        # Rút gọn I: I x -> dịch x
        if f is I:
            result = translate_to_z3(x)
            memo[id(term)] = result
            return result

        # Các trường hợp phức tạp hơn, f phải là một App
        if isinstance(f, App):
            # Rút gọn K: (K y) x -> dịch y
            if f.f is K:
                result = translate_to_z3(f.x)
                memo[id(term)] = result
                return result

            # Rút gọn S: (S g h) x -> dịch ((g x) (h x))
            if isinstance(f.f, App) and f.f.f is S:
                s_g = f.f.x
                s_h = f.x
                # Xây dựng lại biểu thức mới và dịch nó
                new_term = App(App(s_g, x), App(s_h, x))
                result = translate_to_z3(new_term)
                memo[id(term)] = result
                return result

            # Nếu không phải các quy tắc trên, đây là một cấu trúc IF-THEN-ELSE
            # ((Condition Then) Else)
            # Điều kiện là f.f, nhánh Then là f.x, nhánh Else là x
            z3_cond = translate_to_z3(f.f)
            z3_then = translate_to_z3(f.x)
            z3_else = translate_to_z3(x)

            result = If(z3_cond, z3_then, z3_else)
            memo[id(term)] = result
            return result

    # Nếu không có quy tắc nào khớp, đây là một lỗi trong logic của chúng ta
    # hoặc một cấu trúc không mong muốn trong chương trình.
    raise ValueError(f"Không thể dịch biểu thức sang Z3: {term}")


def solve_challenge():
    """Hàm chính để phân tích, dịch và giải bài toán."""
    print("1. Đang đọc và phân tích cú pháp program.txt...")
    try:
        with open('program.txt', 'r') as f:
            src = f.read()
        main_ast = parse(src)[0][1]
    except Exception as e:
        print(f"Lỗi khi đọc hoặc phân tích program.txt: {e}", file=sys.stderr)
        return
    print("   Phân tích cú pháp hoàn tất.")

    print("2. Đang dịch và rút gọn biểu thức sang Z3 (có thể mất một lúc)...")
    try:
        final_formula = translate_to_z3(main_ast)
        print("   Dịch thuật hoàn tất.")
    except (ValueError, RecursionError) as e:
        print(f"\nLỗi trong quá trình dịch thuật: {e}", file=sys.stderr)
        if isinstance(e, RecursionError):
            print("Lỗi đệ quy sâu. Hãy thử tăng giá trị sys.setrecursionlimit() cao hơn nữa.", file=sys.stderr)
        return

    solver = Solver()
    solver.add(final_formula)

    known_prefix = "ictf{"
    known_suffix = "}"
    
    print(f"3. Thêm ràng buộc cho định dạng flag: '{known_prefix}...{known_suffix}'")
    constraints = []
    for i, char in enumerate(known_prefix):
        char_code = ord(char)
        for j in range(8):
            constraints.append(FLAG_BITS[i * 8 + j] == bool((char_code >> (7 - j)) & 1))

    # Flag có 70 ký tự (560 bit), nên vị trí của '}' là 69
    suffix_byte_pos = 69
    char_code = ord(known_suffix)
    for j in range(8):
        constraints.append(FLAG_BITS[suffix_byte_pos * 8 + j] == bool((char_code >> (7 - j)) & 1))

    solver.add(And(constraints))

    print("4. Đang giải công thức bằng Z3...")
    if solver.check() == sat:
        print("   SAT! Đã tìm thấy lời giải.")
        model = solver.model()
        
        flag_bytes = bytearray()
        for i in range(NUM_BITS // 8):
            byte_val = 0
            for j in range(8):
                if model.eval(FLAG_BITS[i * 8 + j], model_completion=True):
                    byte_val |= (1 << (7 - j))
            flag_bytes.append(byte_val)
        
        flag = flag_bytes.decode('ascii', errors='ignore').strip('\x00')

        print("\n" + "="*80)
        print("🎉 Tìm thấy flag! 🎉")
        print(f"  >> {flag}")
        print("="*80)
    else:
        print("   UNSAT. Không tìm thấy lời giải.")

if __name__ == '__main__':
    solve_challenge()