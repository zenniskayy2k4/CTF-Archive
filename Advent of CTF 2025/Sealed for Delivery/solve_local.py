import json
import subprocess
import string
import time
import math
import sys
from functools import reduce
from Crypto.Util.number import long_to_bytes, inverse

# --- CẤU HÌNH ---
CMD = ["python", "-u", "chall.py"]
# CMD = ["python3", "-u", "chall.py"] # Dùng dòng này nếu chạy trên Linux/WSL

def solve():
    print(f"[*] Đang khởi chạy {CMD}...")
    try:
        proc = subprocess.Popen(
            CMD,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        )
    except FileNotFoundError:
        print("[-] Lỗi: Không tìm thấy file. Kiểm tra lại đường dẫn hoặc lệnh python.")
        return

    # Hàm giao tiếp
    def recv_json():
        while True:
            line = proc.stdout.readline()
            if not line: return None
            line = line.strip()
            try:
                if line.startswith("{") and line.endswith("}"):
                    return json.loads(line)
            except: pass

    def send_json(data):
        proc.stdin.write(json.dumps(data) + "\n")
        proc.stdin.flush()

    # Chờ server init
    while True:
        data = recv_json()
        if data and "out" in data and "awaiting query" in data["out"]:
            break
    print("[+] Server Local đã sẵn sàng.")

    def login(u):
        send_json({"option": "login", "username": u, "password": "p"})
        res = recv_json()
        if res and "info" in res:
            return res["info"], res["mac"]
        return None, None

    # Đăng ký
    base_user = "a" * 32
    send_json({"option": "register", "username": base_user, "password": "p", "data": "d"})
    recv_json()

    # =================================================================
    # BƯỚC 1: KHÔI PHỤC P (THUẬT TOÁN MỚI)
    # =================================================================
    print("[*] Đang thu thập mẫu để tìm P (Cần khoảng 20-30s)...")
    samples = {}
    
    # Lấy mẫu
    # Cần sleep để timestamp thay đổi
    count = 0
    while count < 20:
        info, mac_hex = login(base_user)
        if info:
            ts = int.from_bytes(bytes.fromhex(info)[-8:], 'big')
            mac_val = int(mac_hex, 16)
            samples[ts] = mac_val
            sys.stdout.write(f"\r    -> Mẫu: {len(samples)} (Last TS: {ts})")
            sys.stdout.flush()
            count += 1
        time.sleep(1.2) # Sleep > 1s để nhảy giây
    print("\n[+] Đã thu thập xong.")

    # Tìm cặp CHẴN -> LẺ (t, t+1) để XOR diff cố định là 1
    pairs = []
    sorted_ts = sorted(samples.keys())
    for t in sorted_ts:
        if (t % 2 == 0) and ((t + 1) in samples):
            pairs.append((samples[t], samples[t+1]))
    
    print(f"[+] Tìm được {len(pairs)} cặp timestamp hợp lệ.")
    if len(pairs) < 2:
        print("[-] Không đủ cặp dữ liệu. Hãy chạy lại.")
        proc.terminate()
        return

    # --- THUẬT TOÁN TÌM P (BRANCHING GCD) ---
    print("[*] Đang tính toán GCD để tìm P...")
    
    # Lấy cặp đầu tiên làm mốc
    y1_ref, y2_ref = pairs[0]
    
    # Giả thuyết 1: y1*y4 - y2*y3 là bội của P
    # Giả thuyết 2: y1*y4 + y2*y3 là bội của P
    # Ta sẽ thử từng giả thuyết với các cặp còn lại để tìm ra P chung
    
    final_p = 1
    
    # Thử so sánh cặp 0 với cặp 1
    y3, y4 = pairs[1]
    candidates_0 = [
        abs(y1_ref * y4 - y2_ref * y3),
        abs(y1_ref * y4 + y2_ref * y3)
    ]
    
    # Lọc bỏ số 0
    candidates_0 = [x for x in candidates_0 if x > 0]
    
    for start_val in candidates_0:
        current_gcd = start_val
        valid_chain = True
        
        # Kiểm tra consistency với các cặp còn lại
        for i in range(2, len(pairs)):
            y_next_a, y_next_b = pairs[i]
            
            # Tính 2 khả năng của cặp mới so với cặp mốc
            # P phải là ước của (A) hoặc (B)
            val_a = abs(y1_ref * y_next_b - y2_ref * y_next_a)
            val_b = abs(y1_ref * y_next_b + y2_ref * y_next_a)
            
            # Tính GCD với current_gcd
            gcd_a = math.gcd(current_gcd, val_a)
            gcd_b = math.gcd(current_gcd, val_b)
            
            # Chọn đường nào giữ lại được GCD lớn (đặc trưng của P ~ 256 bit)
            # P thật khoảng 256 bit, nên ta ưu tiên kết quả lớn
            if gcd_a > (1 << 200):
                current_gcd = gcd_a
            elif gcd_b > (1 << 200):
                current_gcd = gcd_b
            else:
                # Cả 2 hướng đều ra GCD nhỏ (1 hoặc rác) -> Giả thuyết ban đầu sai
                valid_chain = False
                break
        
        if valid_chain and current_gcd > (1 << 200):
            final_p = current_gcd
            break
            
    # Chuẩn hóa P (vì GCD có thể là k*P)
    # P là số nguyên tố 257 bit. Nếu GCD > 257 bit thì chia bớt các thừa số nhỏ
    while final_p.bit_length() > 258:
        final_p //= 2 # Heuristic: thường thừa số là lũy thừa của 2
        
    print(f"[+] P tìm được: {str(final_p)[:20]}... (Bits: {final_p.bit_length()})")
    
    if final_p.bit_length() < 250:
        print("[-] P không hợp lệ. Có thể do dữ liệu nhiễu.")
        proc.terminate()
        return

    p = final_p

    # =================================================================
    # BƯỚC 2: TÌM G
    # =================================================================
    # (Đoạn này giống cũ nhưng thêm try-except để robust hơn)
    print("[*] Đang tính G...")
    try:
        y1, y2 = pairs[0]
        inv_y1 = inverse(y1, p)
        cand_g = (y2 * inv_y1) % p
        
        # Xác minh G bằng cặp thứ 2
        y3, y4 = pairs[1]
        
        # Các khả năng của G thực sự
        possible_gs = [cand_g, p-cand_g, inverse(cand_g, p), p-inverse(cand_g, p)]
        g = 0
        
        for pg in possible_gs:
            # Check: y4 == y3 * pg (+/-)
            v1 = (y3 * pg) % p
            v2 = (y3 * inverse(pg, p)) % p
            if v1 == y4 or v1 == (p - y4) or v2 == y4 or v2 == (p - y4):
                g = pg
                break
        
        if g == 0:
            print("[-] Cảnh báo: Không xác minh được G, thử dùng candidate đầu tiên.")
            g = cand_g
        
        print(f"[+] G tìm được: {str(g)[:20]}...")

    except Exception as e:
        print(f"[-] Lỗi tính G: {e}")
        proc.terminate()
        return

    # =================================================================
    # BƯỚC 3: GIẢI & FORGE (Code cũ)
    # =================================================================
    # 3.1 s_low
    print("[*] Giải s_low...")
    s_low = 0
    for k in range(16):
        for t1, val1 in samples.items():
            t2 = t1 ^ (1 << k)
            if t2 in samples:
                val2 = samples[t2]
                diff = t1 - t2
                g_factor = pow(g, abs(diff), p)
                if diff < 0: g_factor = inverse(g_factor, p)
                ratio = (val1 * inverse(val2, p)) % p
                if ratio == g_factor or ratio == (p - g_factor):
                    s_low &= ~(1 << k)
                else: s_low |= (1 << k)
                break

    # 3.2 s_high (Rút gọn log)
    print("[*] Giải s_high (Bruteforce)...")
    s_high = 0
    info_base, mac_base = login(base_user)
    ts_base = int.from_bytes(bytes.fromhex(info_base)[-8:], 'big')
    y_base = int(mac_base, 16)
    chars = string.digits + string.ascii_letters + "-_"[:2] # Fix char order bug if needed, but chall uses standard
    chars = string.printable[:62] + "-_"
    
    for k in range(192):
        if k % 50 == 0: sys.stdout.write(f"\r    Bit {k}/192...")
        
        char_idx = k // 6
        bit_idx = k % 6
        new_char_code = 10 ^ (1 << bit_idx) # 'a' is index 10
        
        u_list = list(base_user)
        u_list[char_idx] = chars[new_char_code]
        u_new = "".join(u_list)
        
        send_json({"option": "register", "username": u_new, "password": "p", "data": "d"})
        recv_json()
        info_k, mac_k = login(u_new)
        ts_k = int.from_bytes(bytes.fromhex(info_k)[-8:], 'big')
        y_k = int(mac_k, 16)
        
        # Time fix
        diff_time = ((ts_k & 0xFFFF) ^ s_low) - ((ts_base & 0xFFFF) ^ s_low)
        g_fix = pow(g, abs(diff_time), p)
        if diff_time < 0: g_fix = inverse(g_fix, p)
        y_k_fix = (y_k * inverse(g_fix, p)) % p
        
        g_bit = pow(g, pow(2, k+64, p-1), p)
        ratio = (y_k_fix * inverse(y_base, p)) % p
        
        u_bit_new = (new_char_code >> bit_idx) & 1
        is_match = (ratio == g_bit or ratio == (p - g_bit))
        
        s_bit = 0 if ((is_match and u_bit_new==1) or (not is_match and u_bit_new==0)) else 1
        if s_bit: s_high |= (1 << k)
    print("\n[+] Xong s_high.")

    # 3.3 Forge
    print("[*] Forging Admin...")
    info_final, mac_final = login(base_user)
    y_real = int(mac_final, 16)
    
    def compress(u):
        padded = u.rjust(32, "_")
        val = 0
        for i, c in enumerate(padded): val += chars.index(c) << (6 * i)
        return val

    m_base = compress(base_user)
    m_target = compress("admin")
    exp_diff = ((m_target ^ s_high) - (m_base ^ s_high)) * (1 << 64)
    g_diff = pow(g, abs(exp_diff), p)
    if exp_diff < 0: g_diff = inverse(g_diff, p)
    y_forge = (y_real * g_diff) % p
    if y_forge > p // 2: y_forge = p - y_forge
    
    info_forge = long_to_bytes(m_target, 24) + bytes.fromhex(info_final)[-8:]
    payload = {
        "option": "read", "username": "admin",
        "info": info_forge.hex(), "mac": long_to_bytes(y_forge, 32).hex()
    }
    send_json(payload)
    print("="*40)
    print("RESULT:", recv_json())
    print("="*40)
    proc.terminate()

if __name__ == "__main__":
    solve()