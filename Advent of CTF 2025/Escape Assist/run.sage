import socket
import sys
from bisect import bisect_left
from Crypto.Util.number import long_to_bytes, bytes_to_long

HOST = 'ctf.csd.lol'
PORT = 5000
PAYLOAD = b'flag#' 

def attempt_solve(attempt_count):
    print(f"\n[+] --- Lần thử thứ {attempt_count} ---")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((HOST, PORT))
        s.settimeout(10)
        
        # Nhận dữ liệu
        buffer = b""
        while b"Your integer?" not in buffer:
            chunk = s.recv(4096)
            if not chunk: break
            buffer += chunk
        
        data = buffer.decode('utf-8', errors='ignore')
        
        # Lấy primes
        primes = []
        for line in data.split('\n'):
            parts = line.strip().split()
            if len(parts) >= 40:
                try:
                    candidates = [int(x) for x in parts]
                    if all(x > 1000 for x in candidates):
                        primes = candidates
                        break
                except: continue
        
        if not primes:
            print("[-] Lỗi lấy primes.")
            return False

        # --- TÍNH TOÁN MITM ---
        ps = primes
        N = prod(ps)
        goods = [6, 7] # Chỉ dùng 6 và 7
        
        # Trọng số CRT
        weights = []
        for p in ps:
            M = N // p
            y = inverse_mod(M, p)
            weights.append((M * y) % N)

        # Chia đôi 42 -> 21
        mid = 21
        
        # Nửa Trái
        L = [0]
        for i in range(mid):
            w = weights[i]
            # Tạo danh sách mới bằng cách cộng từng phần tử cũ với (6*w) và (7*w)
            L = [(x + 6*w) % N for x in L] + [(x + 7*w) % N for x in L]
        L.sort()
        
        # Nửa Phải
        R = [0]
        for i in range(mid, 42):
            w = weights[i]
            # Tương tự cho nửa phải
            R = [(x + 6*w) % N for x in R] + [(x + 7*w) % N for x in R]
            
        print(f"[*] Đã tính xong 2 bảng ({len(L)} phần tử mỗi bảng). Đang quét tìm nghiệm...")

        # Xác định các độ dài có thể của N (để padding chính xác)
        n_len = (N.bit_length() + 7) // 8
        possible_lengths = [n_len]
        if N.bit_length() % 8 != 0:
             possible_lengths.append(n_len - 1)

        solution_n = None

        # Quét nửa Phải và tìm khớp trong nửa Trái
        for r_val in R:
            for length in possible_lengths:
                pad_len = length - len(PAYLOAD)
                if pad_len < 0: continue
                
                # Khoảng giá trị mục tiêu: flag#00...00 -> flag#ff...ff
                t_min = bytes_to_long(PAYLOAD + b'\x00' * pad_len)
                t_max = bytes_to_long(PAYLOAD + b'\xff' * pad_len)
                
                if t_min >= N: continue
                t_max = min(t_max, N - 1)
                
                # Tìm l sao cho: t_min <= (l + r) <= t_max (mod N)
                low = (t_min - r_val) % N
                high = (t_max - r_val) % N
                
                candidates = []
                if low <= high:
                    idx = bisect_left(L, low)
                    while idx < len(L) and L[idx] <= high:
                        candidates.append(L[idx])
                        idx += 1
                else:
                    # Wrap around
                    idx = bisect_left(L, low)
                    while idx < len(L):
                        candidates.append(L[idx])
                        idx += 1
                    idx = 0
                    while idx < len(L) and L[idx] <= high:
                        candidates.append(L[idx])
                        idx += 1
                
                for l_val in candidates:
                    n = (l_val + r_val) % N
                    b = long_to_bytes(n)
                    # Kiểm tra kỹ ký tự xuống dòng
                    if b.startswith(PAYLOAD) and b'\n' not in b and b'\r' not in b:
                        solution_n = n
                        break
                if solution_n: break
            if solution_n: break
        
        if solution_n:
            print(f"[!!!] TIM THAY SO N HOP LE !!!")
            print(f"[*] Đang gửi payload...")
            s.sendall(f"{solution_n}\n".encode('utf-8'))
            response = s.recv(4096).decode('utf-8')
            print("Flag:", response.strip())
            return True
        else:
            print("[-] Không tìm thấy nghiệm với bộ primes này. Thử lại...")
            return False

    except Exception as e:
        print(f"Lỗi: {e}")
        return False
    finally:
        s.close()

if __name__ == "__main__":
    count = 1
    while True:
        success = attempt_solve(count)
        if success:
            break
        count += 1