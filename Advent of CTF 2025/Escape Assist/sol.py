import socket
import subprocess
import sys
import os

# --- Cấu hình ---
HOST = 'ctf.csd.lol'
PORT = 5000
# Đường dẫn tới tệp thực thi SageMath. Chỉnh sửa nếu cần.
# Nếu 'sage' đã có trong PATH, bạn có thể để là 'sage'.
SAGE_EXECUTABLE = os.path.expanduser('~/sage/sage-10.5/sage')
PAYLOAD = b'flag#' # Payload ngắn gọn và hiệu quả nhất

# --- Script SageMath sẽ được chạy ---
SAGE_SOLVER_SCRIPT = """
import sys
from Crypto.Util.number import long_to_bytes, bytes_to_long

# Đọc dữ liệu từ Python
input_data = sys.stdin.read().strip().split(',')
ps_str = input_data[:-1]
payload_str = input_data[-1]

ps = [Integer(p) for p in ps_str]
payload = payload_str.encode()
goods = [6, 7, -1, 13]
N = prod(ps)
k = len(ps)

print(f"[Sage] Đã nhận {k} số nguyên tố và payload '{payload.decode()}'.")

# 1. Xây dựng Lattice (theo phương pháp của Heninger-Shacham)
print("[Sage] Đang xây dựng Lattice...")
M = Matrix(ZZ, k + 1, k + 1)
for i in range(k):
    M[i, i] = ps[i]
M[k, :-1] = vector([1] * k)
M[k, k] = 0

# 2. Tạo vector mục tiêu
# Chúng ta muốn n gần với bytes_to_long(payload)
# Cần padding để đủ độ dài bit
total_bits = N.nbits()
total_bytes = (total_bits + 7) // 8
target_bytes = payload.ljust(total_bytes, b'\\x00')
target_val = bytes_to_long(target_bytes)
t = vector([0] * k + [target_val])

# 3. Sử dụng Babai's CVP Algorithm để tìm vector gần nhất
print("[Sage] Đang giải Closest Vector Problem...")
# b is the lattice basis, c is the solution vector in terms of the basis
# v is the found lattice vector
b = M.LLL()
c = t.solve_left(b)
c = vector([round(ci) for ci in c])
v = c * b

# 4. Trích xuất kết quả n từ vector tìm được
# v = (r_0, r_1, ..., r_k-1, n)
# Tuy nhiên, do cách xây dựng lattice, n_found = target_val - v[k]
n_found = target_val - v[k]

# Kiểm tra kết quả
result_bytes = long_to_bytes(n_found, total_bytes)
print(f"[Sage] Đã tìm thấy n, bắt đầu bằng: {result_bytes[:20]}...")

# 5. In kết quả để Python có thể đọc
sys.stdout.write(str(n_found))
sys.stdout.flush()
"""

def solve_with_sage(primes, payload):
    """Gọi SageMath để giải bài toán và trả về số n"""
    print("[Python] Đang gọi SageMath để tính toán...")
    
    # Chuẩn bị dữ liệu để gửi cho Sage
    input_str = ",".join(primes) + "," + payload.decode()
    
    try:
        # Chạy SageMath dưới dạng một tiến trình con
        process = subprocess.Popen(
            [SAGE_EXECUTABLE, '-c', SAGE_SOLVER_SCRIPT],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Gửi dữ liệu vào và nhận kết quả
        stdout, stderr = process.communicate(input=input_str, timeout=120)
        
        if process.returncode != 0:
            print("[Python] Lỗi khi chạy SageMath:")
            print(stderr)
            return None
            
        print("[Python] SageMath đã tính toán xong.")
        return stdout.strip()
        
    except FileNotFoundError:
        print(f"[Python] Lỗi: Không tìm thấy tệp thực thi Sage '{SAGE_EXECUTABLE}'.")
        print("Vui lòng kiểm tra lại đường dẫn SAGE_EXECUTABLE.")
        return None
    except subprocess.TimeoutExpired:
        print("[Python] Lỗi: SageMath chạy quá thời gian.")
        return None

def main():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            print(f"[+] Đã kết nối tới {HOST}:{PORT}")
            
            s.settimeout(10)
            data = s.recv(8192).decode('utf-8')
            if "Your integer?" not in data:
                data += s.recv(4096).decode('utf-8')
            
            # Tách lấy các số nguyên tố
            lines = data.split('\n')
            primes_line = [l for l in lines if ' ' in l and len(l) > 20 and l.strip().split()[0].isdigit()][0]
            primes = primes_line.strip().split()
            print(f"[+] Đã lấy được {len(primes)} số nguyên tố.")
            
            # Gọi SageMath để tìm số n
            n_to_send = solve_with_sage(primes, PAYLOAD)
            
            if not n_to_send:
                print("[-] Không thể tìm thấy số n. Dừng chương trình.")
                return

            print(f"[+] Số n tìm được: {n_to_send[:50]}...")
            
            # Gửi n tới server
            print("[*] Đang gửi số n tới server...")
            s.sendall(f"{n_to_send}\n".encode('utf-8'))
            
            # Nhận cờ
            response = s.recv(4096).decode('utf-8')
            print("\n" + "="*20 + " KẾT QUẢ " + "="*20)
            print(response.strip())
            print("="*48)
            
    except Exception as e:
        print(f"\n[-] Đã xảy ra lỗi: {e}")

if __name__ == "__main__":
    main()