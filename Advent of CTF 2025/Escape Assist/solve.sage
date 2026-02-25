import socket
import sys
import time
from Crypto.Util.number import long_to_bytes, bytes_to_long

HOST = 'ctf.csd.lol'
PORT = 5000

# Cấu hình MITM tối ưu
# Target: "flag " (40 bits) -> Dễ tìm hơn "flag #" rất nhiều
# Boost Left: 4 (RAM ~ 500MB)
# Boost Right: 6 (CPU chịu tải tốt)
# Tổng Entropy: 25 + 27 = 52 bits.
# Dư địa: 52 - 40 = 12 bits -> ~4000 kết quả trùng khớp để tha hồ lọc.

FULL = [6, 7, -1, 13]
RESTRICTED = [6, 7]

def solve_one_attempt():
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((HOST, PORT))
        f = s.makefile('rw')
    except:
        return False

    print(f"[*] Connected. Primes loading...")
    
    primes_line = ""
    while True:
        try:
            line = f.readline().strip()
            if not line: break
            if line[0].isdigit():
                primes_line = line
                break
        except: break
            
    if not primes_line: return False
    
    ps = [int(x) for x in primes_line.split()]
    N = 1
    for p in ps: N *= p
    
    # Target Length = Max Length - 1 byte (Safe Mode)
    SAFE_LEN = (N.bit_length() // 8) - 1
    target_prefix = b"flag " # 5 bytes = 40 bits
    
    # Shift để so sánh 40 bit cao nhất
    SHIFT = (SAFE_LEN - len(target_prefix)) * 8
    
    N_shifted = N >> SHIFT
    # Target value shifted
    pad_len = SAFE_LEN - len(target_prefix)
    target_val = bytes_to_long(target_prefix + b'\x00' * pad_len)
    target_shifted = target_val >> SHIFT
    
    Bs = []
    Bs_shifted = []
    for p in ps:
        Mi = N // p
        yi = pow(Mi, -1, p)
        val = Mi * yi
        Bs.append(val)
        Bs_shifted.append(val >> SHIFT)

    mid = 21
    left_Bs = Bs_shifted[:mid]
    right_Bs = Bs_shifted[mid:]

    # --- LEFT TABLE (Boost 4) ---
    BOOST_L = 4
    left_map = {}
    
    # Iterative Gen Left
    # State: (idx, current_sum, mask)
    stack = [(0, 0, 0)]
    while stack:
        idx, curr, mask = stack.pop()
        if idx == mid:
            left_map[curr] = mask
            continue
            
        choices = FULL if idx < BOOST_L else RESTRICTED
        b = left_Bs[idx]
        
        for i, val in enumerate(choices):
            # Tính tổng và mask
            # Mask encoding: Boost dùng 2 bit, Restr dùng 1 bit
            nxt_sum = (curr + val * b)
            if nxt_sum >= N_shifted: nxt_sum %= N_shifted
            elif nxt_sum < 0: nxt_sum %= N_shifted
            
            if idx < BOOST_L: nxt_mask = (mask << 2) | i
            else: nxt_mask = (mask << 1) | i
            
            stack.append((idx + 1, nxt_sum, nxt_mask))
            
    # --- RIGHT SCAN (Boost 6) ---
    BOOST_R = 6
    tolerances = [0, 1, -1]
    
    # Recursive Right Check
    found_flag = False
    
    def check_right(idx, curr, choices_list):
        nonlocal found_flag
        if found_flag: return

        if idx == len(right_Bs):
            needed = (target_shifted - curr) % N_shifted
            
            for tol in tolerances:
                check = (needed + tol) % N_shifted
                if check in left_map:
                    # Potential Match found!
                    mask_l = left_map[check]
                    
                    # Reconstruct Left
                    l_choices = []
                    tmp = mask_l
                    # Decode Restricted (reverse order)
                    for _ in range(mid - 1, BOOST_L - 1, -1):
                        l_choices.append(RESTRICTED[tmp & 1])
                        tmp >>= 1
                    # Decode Boost
                    for _ in range(BOOST_L - 1, -1, -1):
                        l_choices.append(FULL[tmp & 3])
                        tmp >>= 2
                    l_choices.reverse()
                    
                    full_rs = l_choices + choices_list
                    final_n = sum(r * b for r, b in zip(full_rs, Bs)) % N
                    
                    payload = long_to_bytes(final_n)
                    
                    # --- CRITICAL FILTERS ---
                    # 1. Check strict prefix "flag #"
                    if not payload.startswith(b"flag #"):
                        continue
                        
                    # 2. Check bad bytes
                    if b'\x00' in payload or b'\n' in payload or b'\r' in payload:
                        continue
                        
                    print(f"\n[+] PAYLOAD FOUND: {payload[:30]}...")
                    f.write(str(final_n) + "\n")
                    f.flush()
                    
                    # Read Flag
                    while True:
                        resp = f.readline()
                        if not resp: break
                        if "{" in resp:
                            print(f"\n[SUCCESS] FLAG: {resp.strip()}")
                            found_flag = True
                            return
            return

        choices = FULL if idx < BOOST_R else RESTRICTED
        b = right_Bs[idx]
        
        for val in choices:
            nxt = (curr + val * b)
            if nxt >= N_shifted: nxt %= N_shifted
            elif nxt < 0: nxt %= N_shifted
            
            choices_list.append(val)
            check_right(idx + 1, nxt, choices_list)
            if found_flag: return
            choices_list.pop()

    check_right(0, 0, [])
    
    if found_flag: return True
    print("[-] Attempt failed (bad luck). Retrying...")
    s.close()
    return False

if __name__ == "__main__":
    sys.setrecursionlimit(5000)
    attempt = 0
    while True:
        attempt += 1
        print(f"\n=== ATTEMPT {attempt} ===")
        if solve_one_attempt():
            break
        time.sleep(1)