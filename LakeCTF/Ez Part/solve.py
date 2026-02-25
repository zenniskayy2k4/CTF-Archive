import requests
import json
from Crypto.Util.number import bytes_to_long, long_to_bytes, isPrime, GCD
import sys
import random
import string
from hashlib import sha256
import itertools
import time

HOST = "http://chall.polygl0ts.ch:6027"
ALPHABET = string.ascii_letters + string.digits
PASSWORD_LEN = 192 # Độ dài an toàn
s = requests.Session()

# Cache hash sha256 của các ký tự để tăng tốc
CHAR_HASHES = {} 

def get_masks():
    try:
        return s.get(f"{HOST}/masks", timeout=10).json()['masks']
    except Exception as e:
        sys.exit(f"[-] Lỗi kết nối: {e}")

def get_b_val(user, pwd):
    try:
        s.post(f"{HOST}/create-account", json={"username": user, "password": pwd})
        r = s.post(f"{HOST}/prove-id", json={"username": user, "password": "x"})
        if r.status_code != 401: return None
        msg = r.json()['message']
        line = [l for l in msg.split('\n') if l.startswith("Wrong b:")][0]
        return int(line.split(": ")[1])
    except: return None

def recover_p():
    print("[*] Đang khôi phục p (GCD)...")
    rnd = ''.join(random.choices(string.ascii_lowercase, k=4))
    b1 = get_b_val(f"fast1_{rnd}", "yy")
    b2 = get_b_val(f"fast2_{rnd}", "zz")
    if not b1 or not b2: sys.exit("[-] Lỗi lấy b.")
    
    val1 = pow(3, bytes_to_long(b"yy")) - b1
    val2 = pow(3, bytes_to_long(b"zz")) - b2
    g = GCD(val1, val2)
    p = g
    for i in [2, 3, 5, 7, 11, 13, 17, 19]:
        while p % i == 0: p //= i
    print(f"[+] p = {p}")
    return p

def get_admin_data():
    r = s.post(f"{HOST}/prove-id", json={"username": "admin", "password": "A"})
    msg = r.json()['message']
    lines = msg.split('\n')
    b_val = int([l for l in lines if l.startswith("Wrong b:")][0].split(": ")[1])
    hashes = {}
    for l in lines:
        if l.startswith("Wrong mask :"):
            p = l.split(" : ")[1].split(",")
            hashes[int(p[0])] = p[1]
    return b_val, hashes

def solve_x_low(b, p):
    print("[*] Giải 150 bit thấp...")
    k = 150
    factor = (p - 1) // (2**k)
    g_p = pow(3, factor, p)
    h_p = pow(b, factor, p)
    x = 0
    curr = h_p
    for i in range(k):
        e = pow(curr, 1 << (k - 1 - i), p)
        bit = 1 if e == p - 1 else 0
        x |= (bit << i)
        if bit:
            inv = pow(g_p, (2**k) - (1 << i), p)
            curr = (curr * inv) % p
    return x

# --- Optimized Solver ---

def get_candidates(idx, x_low_bits):
    # Trả về các ký tự hợp lệ cho vị trí index
    # idx 173 (tính từ 0) là byte chứa bits 144-151.
    # bits 144-149 của x_low_bits là CỐ ĐỊNH.
    # byte & 0x3F phải bằng (x_low >> 144) & 0x3F
    
    target_idx = PASSWORD_LEN - 19 # 192 - 19 = 173
    
    if idx == target_idx:
        req = (x_low_bits >> 144) & 0x3F
        return [c for c in ALPHABET_CODES if (c & 0x3F) == req]
    return ALPHABET_CODES

ALPHABET_CODES = [ord(c) for c in ALPHABET]

def solve_recursive(known_bytes, parsed_masks, x_low_bits, depth=0):
    # 1. Consistency Check & Mask Selection
    # Tìm mask nào có thể kiểm tra ngay lập tức (0 unknowns) hoặc sắp kiểm tra được
    
    # Priority Queue cho mask: (số byte thiếu, index mask)
    mask_queue = []
    
    for m_idx, m_data in enumerate(parsed_masks):
        # Tính số byte thiếu
        unknowns = []
        base_val = 0
        is_violated = False
        
        for b_idx, shift in m_data['byte_map']:
            val = known_bytes[b_idx]
            if val is None:
                unknowns.append(b_idx)
            else:
                base_val |= (val << shift)
        
        if not unknowns:
            # Mask đã đầy đủ -> Validate
            if sha256(str(base_val & m_data['val']).encode()).hexdigest() != m_data['target']:
                return None # Backtrack
        else:
            mask_queue.append((len(unknowns), m_idx, unknowns, base_val))
    
    # Nếu không còn mask nào chưa giải -> Kiểm tra xem đã điền hết byte chưa?
    # Nếu chưa, ta phải đoán các byte còn lại (ưu tiên byte cạnh vùng đã biết)
    if not mask_queue:
        if any(b is None for b in known_bytes):
            # Tìm byte chưa biết lớn nhất (gần vùng đã biết nhất, duyệt ngược)
            # Vùng đã biết nằm ở cuối (index cao). Ta tìm index cao nhất mà là None.
            for i in range(PASSWORD_LEN - 1, -1, -1):
                if known_bytes[i] is None:
                    # Đoán byte này
                    candidates = get_candidates(i, x_low_bits)
                    for val in candidates:
                        known_bytes[i] = val
                        res = solve_recursive(known_bytes, parsed_masks, x_low_bits, depth+1)
                        if res: return res
                        known_bytes[i] = None
                    return None
        return known_bytes

    # 2. Chọn mask tốt nhất để giải (ít ẩn số nhất)
    mask_queue.sort(key=lambda x: x[0])
    best_count, m_idx, unknowns, base_val = mask_queue[0]
    m_data = parsed_masks[m_idx]
    
    # Nếu số ẩn số quá lớn (> 4), ta không brute-force mask này trực tiếp.
    # Thay vào đó, ta đoán 1 biến trong unknowns (ưu tiên biến cao nhất - gần biên giới nhất)
    # để giảm độ khó cho đệ quy sau.
    
    LIMIT = 4
    if best_count > LIMIT:
        # Chọn biến cao nhất (index lớn nhất) để đoán -> Hy vọng nó liên kết với vùng đã biết
        unknowns.sort(reverse=True) # Sort index giảm dần
        target_idx = unknowns[0]
        
        # Logging để người dùng biết không bị treo
        if depth < 5:
            sys.stdout.write(f"\r[*] Depth {depth}: Đoán byte {target_idx} (còn thiếu {best_count} byte trong mask {m_idx})...   ")
            sys.stdout.flush()
            
        candidates = get_candidates(target_idx, x_low_bits)
        for val in candidates:
            known_bytes[target_idx] = val
            res = solve_recursive(known_bytes, parsed_masks, x_low_bits, depth+1)
            if res: return res
            known_bytes[target_idx] = None
        return None
        
    else:
        # Brute-force mask này (<= 4 bytes)
        # Tạo ranges
        ranges = [get_candidates(u, x_low_bits) for u in unknowns]
        
        valid_combos = []
        for p in itertools.product(*ranges):
            test_val = base_val
            for i, val in enumerate(p):
                # Lấy shift từ byte_map của mask
                # Cần tìm lại shift cho byte unknowns[i]
                # (Hơi chậm nếu loop, optimize bằng dict? Ko cần vì count nhỏ)
                # Dùng m_data['byte_map']
                u_idx = unknowns[i]
                shift = next(s for b, s in m_data['byte_map'] if b == u_idx)
                test_val |= (val << shift)
            
            if sha256(str(test_val & m_data['val']).encode()).hexdigest() == m_data['target']:
                valid_combos.append(p)
        
        # Thử các combo hợp lệ
        for combo in valid_combos:
            # Apply
            for i, val in enumerate(combo): known_bytes[unknowns[i]] = val
            
            res = solve_recursive(known_bytes, parsed_masks, x_low_bits, depth+1)
            if res: return res
            
            # Backtrack
            for i, val in enumerate(combo): known_bytes[unknowns[i]] = None
            
        return None

def main():
    sys.setrecursionlimit(5000)
    p = recover_p()
    admin_b, mask_hashes = get_admin_data()
    masks = get_masks()
    x_low = solve_x_low(admin_b, p)
    
    print("[*] Pre-processing masks...")
    
    # Điền 18 byte cuối
    known_bytes = [None] * PASSWORD_LEN
    low_bytes = long_to_bytes(x_low)
    SAFE_BYTES = 18
    if len(low_bytes) >= SAFE_BYTES:
        safe_part = low_bytes[-SAFE_BYTES:]
        offset = PASSWORD_LEN - len(safe_part)
        for i in range(len(safe_part)):
            known_bytes[offset + i] = safe_part[i]
            
    # Parse masks cấu trúc hiệu quả
    parsed_masks = []
    for idx, (h, shift) in enumerate(masks):
        target = mask_hashes.get(idx)
        if not target: continue
        
        m_val = int(h, 16) << shift
        # Map byte index -> shift amount
        byte_map = []
        for b_idx in range(PASSWORD_LEN):
            bit_offset = (PASSWORD_LEN - 1 - b_idx) * 8
            # Check if mask covers this byte
            if (m_val >> bit_offset) & 0xFF:
                byte_map.append((b_idx, bit_offset))
                
        parsed_masks.append({
            'val': m_val, 'target': target, 'byte_map': byte_map, 'orig_idx': idx
        })
        
    print(f"[i] {len(parsed_masks)} masks active. Bắt đầu giải...")
    
    start_time = time.time()
    final_bytes = solve_recursive(known_bytes, parsed_masks, x_low)
    print(f"\n[+] Giải xong trong {time.time() - start_time:.2f}s")
    
    if final_bytes:
        res = bytearray()
        for b in final_bytes:
            if b is not None: res.append(b)
            else: res.append(0)
        
        # Trim nulls
        start = 0
        while start < len(res) and res[start] == 0: start += 1
        pwd = bytes_to_long(res[start:]).to_bytes((len(res)-start), 'big').decode()
        
        print(f"\n[+] PASSWORD: {pwd}")
        r = s.post(f"{HOST}/prove-id", json={"username": "admin", "password": pwd})
        print(f"[+] FLAG: {r.json().get('message')}")
    else:
        print("[-] Không tìm thấy lời giải. Hãy thử chạy lại script (p có thể thay đổi).")

if __name__ == "__main__":
    main()