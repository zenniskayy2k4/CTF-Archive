import socket
import random as sys_random
import time
from Crypto.Util.number import long_to_bytes, bytes_to_long
from sage.all import *

HOST = 'ctf.csd.lol'
PORT = 5000

# Tập hợp các số dư server chấp nhận
VALID_GOODS = [6, 7, -1, 13]

def solve():
    print(f"[*] Target: {HOST}:{PORT}")
    
    while True:
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((HOST, PORT))
            
            # 1. Nhận Primes
            buffer = b""
            while b"Your integer?" not in buffer:
                try:
                    chunk = s.recv(4096)
                    if not chunk: break
                    buffer += chunk
                except: break
            
            lines = buffer.decode(errors='ignore').split('\n')
            primes_str = lines[0] if lines else ""
            try:
                primes = [Integer(x) for x in primes_str.split() if x.replace('-','').isdigit()]
            except:
                if s: s.close(); continue

            if len(primes) < 40:
                if s: s.close(); continue
                
            N = prod(primes)
            k = len(primes)
            
            # 2. Setup Target: "Gravity Well"
            # Chúng ta target chuỗi: "flag#" + rất nhiều dấu cách (0x20)
            # LLL sẽ cố gắng tìm số n có các byte xấp xỉ 0x20.
            # Điều này giúp tránh xa 0x00 (Null) và 0x80+ (UTF-8 Error)
            
            prefix = b'flag#'
            # Tính độ dài byte của N
            total_bytes = (N.nbits() + 7) // 8
            padding_len = total_bytes - len(prefix)
            
            # Tạo target value gồm toàn dấu cách ở phần đuôi
            target_bytes = prefix + b' ' * padding_len
            target_val = bytes_to_long(target_bytes)
            
            # Cắt bớt bit thừa để khớp với N
            if target_val >= N:
                target_val %= N # Hoặc shift bit, nhưng % N an toàn hơn cho target gần đúng
            
            print(f"[*] Primes: {k} | Mode: Space Padding Gravity Well")

            # 3. CRT Precompute
            C = []
            for p in primes:
                M_i = N // p
                y_i = inverse_mod(M_i, p)
                C.append(M_i * y_i)

            valid_candidate = None
            
            # 4. Hunting Loop
            # Thường chỉ mất < 20 lần thử là ra vì xác suất rơi vào vùng an toàn rất cao
            for attempt in range(50):
                # Chọn ngẫu nhiên 2 số từ goods cho mỗi prime (Binary Knapsack)
                # Đảm bảo 100% n % p thuộc goods
                chosen_pairs = []
                for _ in range(k):
                    pair = sys_random.sample(VALID_GOODS, 2)
                    chosen_pairs.append(pair)
                
                base_sum = 0
                diffs = []
                
                for i in range(k):
                    val0, val1 = chosen_pairs[i]
                    base_sum = (base_sum + val0 * C[i]) % N
                    diff = ((val1 - val0) * C[i]) % N
                    diffs.append(diff)
                
                target_diff = (target_val - base_sum) % N
                
                # Lattice Construction
                dim = k + 1
                M = Matrix(ZZ, dim, dim)
                SCALE = 2**100 
                
                for i in range(k):
                    M[i, i] = 2 
                    M[i, k] = diffs[i] * SCALE
                
                M[k, k] = N * SCALE
                T = vector(ZZ, [1]*k + [target_diff * SCALE])
                
                # Giải CVP
                B = M.LLL()
                
                try:
                    # Babai Rounding
                    B_real = B.change_ring(RR)
                    T_real = T.change_ring(RR)
                    coeffs = T_real * B_real.inverse()
                    coeffs_round = vector(ZZ, [round(c) for c in coeffs])
                    closest = coeffs_round * B
                    
                    found_diff_val = closest[k] // SCALE
                    candidate = (base_sum + found_diff_val) % N
                    
                    payload = long_to_bytes(candidate)
                    
                    # --- BỘ LỌC AN TOÀN ---
                    # 1. Check Prefix
                    if not payload.startswith(b'flag#'):
                        continue
                        
                    # 2. Check Null Bytes (Sát thủ số 1 của eval)
                    if b'\x00' in payload:
                        continue
                        
                    # 3. Check UTF-8 (Sát thủ số 2)
                    try:
                        decoded = payload.decode('utf-8')
                        # 4. Check Newline (Sát thủ số 3)
                        # Chỉ cần check đoạn đầu, đoạn sau comment không quan trọng lắm
                        # nhưng an toàn nhất là không có newline nào
                        if '\n' in decoded or '\r' in decoded:
                            continue
                    except UnicodeDecodeError:
                        continue 

                    print(f"\n[!!!] FOUND PERFECT CLEAN PAYLOAD (Attempt {attempt})")
                    print(f"[+] Payload Start: {payload[:20]}...")
                    valid_candidate = candidate
                    break

                except Exception as e:
                    pass
            
            if valid_candidate:
                print(f"[+] Sending integer...")
                s.sendall(str(valid_candidate).encode() + b"\n")
                
                response = b""
                try:
                    while True:
                        chunk = s.recv(4096)
                        if not chunk: break
                        response += chunk
                        print(chunk.decode(errors='ignore'), end="")
                        if b'}' in response: break
                except: pass
                
                if b'csd{' in response or b'flag' in response:
                    print("\n\n[!!!] CONGRATULATIONS [!!!]")
                    s.close()
                    return
                else:
                    print("\n[-] No flag returned. Retrying connection...")
            else:
                print("\n[-] Batch finished. Re-rolling...")
            
            s.close()
            
        except KeyboardInterrupt:
            print("\n[!] User stopped.")
            break
        except Exception as e:
            if s: s.close()

if __name__ == '__main__':
    solve()