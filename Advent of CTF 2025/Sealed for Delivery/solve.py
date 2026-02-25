import json
import socket
import string
import time
import math
import sys
from Crypto.Util.number import long_to_bytes, inverse

HOST = 'ctf.csd.lol'
PORT = 2020

def solve():
    print(f"[*] Connecting {HOST}:{PORT}...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((HOST, PORT))
    except Exception as e:
        print(f"[-] Connection error: {e}")
        return

    # Buffer to handle TCP stream (avoid packet splitting)
    buffer = ""
    def recv_json():
        nonlocal buffer
        while True:
            if "\n" in buffer:
                line, buffer = buffer.split("\n", 1)
                try:
                    return json.loads(line)
                except:
                    continue
            try:
                chunk = s.recv(4096).decode()
                if not chunk: return None
                buffer += chunk
            except:
                return None

    def send_json(data):
        s.sendall((json.dumps(data) + "\n").encode())

    # 1. Initialization
    print("[*] Waiting for Server response...")
    while True:
        data = recv_json()
        if data and "out" in data and "awaiting query" in data["out"]:
            break
    print("[+] Server is ready for attack.")

    def login(u):
        send_json({"option": "login", "username": u, "password": "p"})
        res = recv_json()
        if res and "info" in res:
            return res["info"], res["mac"]
        return None, None

    # Đăng ký user mẫu
    base_user = "a" * 32
    send_json({"option": "register", "username": base_user, "password": "p", "data": "d"})
    recv_json()

    # STEP 1: RECOVER P (MODULUS)
    print("[*] Collecting Timestamp samples (Server is slow, please be patient)...")
    samples = {}
    
    target_samples = 25 
    for i in range(target_samples):
        info, mac_hex = login(base_user)
        if info:
            ts = int.from_bytes(bytes.fromhex(info)[-8:], 'big')
            mac_val = int(mac_hex, 16)
            samples[ts] = mac_val
            sys.stdout.write(f"\r    -> Sample: {len(samples)}/{target_samples} (Last TS: {ts})")
            sys.stdout.flush()
        
        time.sleep(0.5) 

    # Filter pairs (t, t+1) with even t
    pairs = []
    sorted_ts = sorted(samples.keys())
    for t in sorted_ts:
        if (t % 2 == 0) and ((t + 1) in samples):
            pairs.append((samples[t], samples[t+1]))
    
    print(f"\n[+] Found {len(pairs)} valid timestamp pairs (Even->Odd).")
    if len(pairs) < 2:
        print("[-] Not enough pair data. Please retry or increase sample size.")
        return

    # --- ALGORITHM TO FIND P (BRANCHING GCD) ---
    print("[*] Calculating P...")
    y1_ref, y2_ref = pairs[0]
    
    # Create candidates from the first pair
    candidates_0 = [
        abs(y1_ref * pairs[1][1] - y2_ref * pairs[1][0]), # Cross product với cặp thứ 2
        abs(y1_ref * pairs[1][1] + y2_ref * pairs[1][0])
    ]
    candidates_0 = [x for x in candidates_0 if x > 0]
    
    final_p = 1
    
    # Iterate through hypotheses
    for start_val in candidates_0:
        current_gcd = start_val
        valid_chain = True
        
        # Check with all remaining pairs
        for i in range(2, len(pairs)):
            y_next_a, y_next_b = pairs[i]
            val_a = abs(y1_ref * y_next_b - y2_ref * y_next_a)
            val_b = abs(y1_ref * y_next_b + y2_ref * y_next_a)
            
            gcd_a = math.gcd(current_gcd, val_a)
            gcd_b = math.gcd(current_gcd, val_b)
            
            # Ưu tiên GCD lớn (~256 bit)
            if gcd_a > (1 << 240):
                current_gcd = gcd_a
            elif gcd_b > (1 << 240):
                current_gcd = gcd_b
            else:
                valid_chain = False
                break
        
        if valid_chain and current_gcd > (1 << 240):
            final_p = current_gcd
            break
            
    # Chuẩn hóa P
    while final_p.bit_length() > 258:
        final_p //= 2
        
    print(f"[+] Found P: {str(final_p)[:20]}... (Bits: {final_p.bit_length()})")
    if final_p.bit_length() < 250:
        print("[-] P found is too small or incorrect. Server might be lagging, please retry.")
        return
    p = final_p

    # STEP 2: FIND G (GENERATOR)
    print("[*] Calculating G...")
    try:
        y1, y2 = pairs[0]
        inv_y1 = inverse(y1, p)
        cand_g = (y2 * inv_y1) % p
        
        # Verify
        possible_gs = [cand_g, p-cand_g, inverse(cand_g, p), p-inverse(cand_g, p)]
        g = 0
        y3, y4 = pairs[1]
        
        for val in possible_gs:
            v1 = (y3 * val) % p
            v2 = (y3 * inverse(val, p)) % p
            if v1 == y4 or v1 == (p - y4) or v2 == y4 or v2 == (p - y4):
                g = val
                break
        if g == 0: g = cand_g # Fallback
        print(f"[+] Found G: {str(g)[:20]}...")
    except:
        print("[-] Error calculating G.")
        return

    # STEP 3: SOLVE SECRET AND FORGE
    # 3.1. s_low
    print("[*] Solving s_low...")
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

    # 3.2. s_high
    print("[*] Solving s_high (Bruteforce 192 bits - Takes about 2-3 minutes)...")
    s_high = 0
    
    # Get the latest base
    info_base, mac_base = login(base_user)
    ts_base = int.from_bytes(bytes.fromhex(info_base)[-8:], 'big')
    y_base = int(mac_base, 16)
    
    printable = string.digits + string.ascii_letters
    chars = printable[:62] + "-_"

    for k in range(192):
        if k % 10 == 0: sys.stdout.write(f"\r    Progress: {k}/192 bits...")
        
        char_idx = k // 6
        bit_idx = k % 6
        new_char_code = 10 ^ (1 << bit_idx) # 'a' is index 10
        
        u_list = list(base_user)
        u_list[char_idx] = chars[new_char_code]
        u_new = "".join(u_list)
        
        send_json({"option": "register", "username": u_new, "password": "p", "data": "d"})
        recv_json() # consume
        
        info_k, mac_k = login(u_new)
        ts_k = int.from_bytes(bytes.fromhex(info_k)[-8:], 'big')
        y_k = int(mac_k, 16)
        
        # Time correction
        t_xor_sk = (ts_k & 0xFFFF) ^ s_low
        t_xor_sb = (ts_base & 0xFFFF) ^ s_low
        diff_time = t_xor_sk - t_xor_sb
        
        g_fix = pow(g, abs(diff_time), p)
        if diff_time < 0: g_fix = inverse(g_fix, p)
        y_k_fix = (y_k * inverse(g_fix, p)) % p
        
        g_bit = pow(g, pow(2, k+64, p-1), p)
        ratio = (y_k_fix * inverse(y_base, p)) % p
        
        u_bit_new = (new_char_code >> bit_idx) & 1
        is_match = (ratio == g_bit or ratio == (p - g_bit))
        
        s_bit = 0 if ((is_match and u_bit_new==1) or (not is_match and u_bit_new==0)) else 1
        if s_bit: s_high |= (1 << k)

    print("\n[+] s_high completed.")

    # 3.3. Forge
    print("[*] Sending payload to get the flag...")
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
    
    send_json({
        "option": "read",
        "username": "admin",
        "info": info_forge.hex(),
        "mac": long_to_bytes(y_forge, 32).hex()
    })
    
    res = recv_json()
    print("FLAG:", res)
    s.close()

if __name__ == "__main__":
    solve()