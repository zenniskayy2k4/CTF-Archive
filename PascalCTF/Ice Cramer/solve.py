from pwn import *
import numpy as np
import re

# Cấu hình kết nối
HOST = 'cramer.ctf.pascalctf.it'
PORT = 5002

def solve():
    # Kết nối đến server
    print(f"[*] Connecting to {HOST}:{PORT}...")
    r = remote(HOST, PORT)

    # Đọc dữ liệu từ server cho đến dòng nhắc nhở cuối cùng
    print("[*] Receiving data...")
    # Server in ra các phương trình rồi đến dòng "Solve the system..."
    data = r.recvuntil(b"Solve the system of equations to find the flag!").decode()
    
    # Tách các dòng dữ liệu
    lines = data.strip().split('\n')
    
    # Lọc ra các dòng là phương trình (chứa 'x_0' và dấu '=')
    equations = [l for l in lines if 'x_0' in l and '=' in l]
    
    n = len(equations)
    if n == 0:
        print("[-] No equations found in response.")
        return

    print(f"[*] Found {n} equations. Flag length is likely {n}.")
    
    # Khởi tạo ma trận hệ số A và vector kết quả B
    # Hệ phương trình: A * X = B
    A = np.zeros((n, n))
    B = np.zeros(n)
    
    # Parse từng phương trình
    # Dạng: -45*x_0 + 12*x_1 + ... = 1234
    for row_idx, line in enumerate(equations):
        # Tách vế trái (biến số) và vế phải (kết quả)
        parts = line.split('=')
        lhs = parts[0]
        rhs = int(parts[1].strip())
        
        # Lưu kết quả vào vector B
        B[row_idx] = rhs
        
        # Dùng regex để tìm tất cả các cặp (hệ số, chỉ số biến)
        # Pattern: (số nguyên bao gồm dấu âm)*x_(chỉ số)
        # Ví dụ khớp: "-45" và "0" từ chuỗi "-45*x_0"
        matches = re.findall(r'(-?\d+)\*x_(\d+)', lhs)
        
        for coeff, var_idx in matches:
            col_idx = int(var_idx)
            val = int(coeff)
            # Điền vào ma trận A tại hàng hiện tại, cột tương ứng với biến
            if col_idx < n:
                A[row_idx][col_idx] = val
            
    # Giải hệ phương trình tuyến tính
    print("[*] Solving linear system...")
    try:
        # X = inverse(A) * B
        X = np.linalg.solve(A, B)
        
        # Chuyển đổi nghiệm số thực về số nguyên (ASCII) rồi thành ký tự
        flag_content = ""
        for x in X:
            # Làm tròn vì kết quả phép chia có thể là float (ví dụ 99.99999 -> 100)
            char_code = int(np.round(x))
            flag_content += chr(char_code)
            
        print(f"\n[+] Flag content decoded: {flag_content}")
        print(f"[+] Full Flag: pascalCTF{{{flag_content}}}")
        
    except np.linalg.LinAlgError:
        print("[-] Error: Singular matrix (system cannot be solved uniqueley).")
    except Exception as e:
        print(f"[-] Error: {e}")

    r.close()

if __name__ == "__main__":
    solve()