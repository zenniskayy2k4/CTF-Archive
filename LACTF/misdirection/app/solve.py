import requests
import time
import numpy as np
import hashlib
from Crypto.Util.number import long_to_bytes

# --- CONFIGURATION ---
URL = "http://localhost:8000"
N_KEY = 251        # We use the short key length
N_SERVER = 545     # Server verifies up to this length
Q = 128
BOUND_CHECK = 545  # The target Norm

def get_session():
    return requests.Session()

def parse_pub_key(pub_key_str):
    lines = pub_key_str.strip().split('\n')
    coeff_line = ""
    for line in lines:
        if "|" in line and "==" not in line:
            if len(line) > len(coeff_line): coeff_line = line
    if not coeff_line: return []
    return [int(x) for x in coeff_line.strip().split('|')]

# Helper to reproduce the server's H function accurately
def H_poly(msg_bytes, N):
    h = hashlib.sha1()
    i = 0
    m = ""
    while len(m) < N:
        h_obj = h.copy() # Branch off hash state if needed, but standard logic assumes new update
        # Re-reading NTRU.py snippet: H creates new hash object, updates with msg+counter
        h_temp = hashlib.sha1()
        h_temp.update(msg_bytes + str(i).encode("ascii"))
        m += h_temp.hexdigest()
        i += 1
    
    coeffs = [0] * N
    for i in range(len(m)):
        coeffs[i % N] += ord(m[i])
    return coeffs

def solve_challenge():
    s = get_session()
    print(f"[*] Connecting to {URL} ...")

    # --- STEP 1: KEY SETUP ---
    # We need a key where h[0] is odd (invertible mod 128) for linear solving
    h_coeffs = []
    h0_inv = 0
    
    while True:
        try:
            print("[*] Checking key properties...")
            # We assume the current key is fresh or we reset if needed
            resp = s.get(f"{URL}/public-key")
            if resp.status_code != 200: 
                s.get(f"{URL}/regenerate-keys"); time.sleep(2); continue
            
            h_coeffs = parse_pub_key(resp.json()['public-key'])
            
            # Check if h[0] is odd
            if h_coeffs[0] % 2 == 0:
                print(f"[!] Key starts with even number ({h_coeffs[0]}). Regenerating...")
                s.get(f"{URL}/regenerate-keys")
                time.sleep(2)
                continue
            
            # Calculate modular inverse of h[0]
            h0_inv = pow(h_coeffs[0], -1, Q)
            print(f"[*] Good key found! h[0]={h_coeffs[0]}")
            break
        except Exception as e:
            print(f"Error: {e}. Retrying...")
            time.sleep(1)

    # --- STEP 2: ATTACK LOOP ---
    try:
        curr_count = s.get(f"{URL}/current-count").json()['count']
        current_sig = s.get(f"{URL}/zero-signature").json()['signature']
    except:
        curr_count = 0
        current_sig = "" # Will fail if not 0
    
    print(f"[*] Starting attack from Level {curr_count}")
    
    for i in range(curr_count, 14):
        print(f"\n[+] Growing snake to {i+1}...")
        
        # 1. Update Server
        resp = s.post(f"{URL}/grow", json={"count": i, "sig": current_sig}).json()
        
        if "msg" in resp and "Invalid" in resp["msg"]:
            print(f"[-] FATAL: Server rejected previous signature. Resetting...")
            s.get(f"{URL}/regenerate-keys")
            time.sleep(2)
            return solve_challenge()

        target = i + 1
        if target == 14: break # We are done!
            
        print(f"[*] Forging signature for {target}...")
        msg = long_to_bytes(target)
        
        # 2. Brute Force r
        # We need Norm(s) < 545 AND Norm(Tail_Error) < 545.
        attempt = 0
        while True:
            attempt += 1
            r = np.random.randint(0, 1<<30)
            
            # A. Generate Hash t
            # We generate slightly more than N_KEY to cover the immediate convolution check
            # But strictly we need full N_SERVER for tail check.
            # Optimization: Generate full t only if s is promising? 
            # Generating t is fast enough.
            t = H_poly(msg + str(r).encode(), N_SERVER)
            
            # B. Solve Linear System for s (Length 251)
            # s[k] = (t[k] - sum(s[j]*h[k-j])) * h[0]^-1
            # We do this for k = 0 to 250
            s_sol = [0] * N_KEY
            s_norm_sq = 0
            possible = True
            
            for k in range(N_KEY):
                prev_sum = 0
                # Convolution sum: sum(s[j] * h[k-j])
                # Optimization: iterate j backwards from k
                # h index is k-j. We need h index >= 0. So j <= k.
                start_j = max(0, k - (len(h_coeffs) - 1))
                for j in range(start_j, k):
                    prev_sum = (prev_sum + s_sol[j] * h_coeffs[k-j])
                
                # Solve for s[k]
                val = (t[k] - prev_sum) * h0_inv
                val %= Q
                s_sol[k] = val
                
                # Update Norm(s) on the fly
                centered = val if val <= Q//2 else val - Q
                s_norm_sq += centered * centered
                
                # Optimization: Fail fast if Norm(s) already too big
                if s_norm_sq >= BOUND_CHECK**2:
                    possible = False
                    break
            
            if not possible:
                continue

            s_norm = np.sqrt(s_norm_sq)
            
            # C. Check Tail Error
            # We matched t for 0..250. Now check error for 251..544
            # Error[k] = (s*h)[k] - t[k]
            # Since s is fixed (and 0 for k>=251), (s*h)[k] is just the tail of convolution
            
            tail_norm_sq = 0
            for k in range(N_KEY, N_SERVER):
                sh_val = 0
                # s exists for 0..250. h exists for 0..250.
                # h_idx = k - j. Need 0 <= h_idx <= 250.
                # => j >= k - 250.
                # also j <= 250 (max s index)
                start_j = max(0, k - (len(h_coeffs) - 1))
                end_j = min(N_KEY - 1, k)
                
                for j in range(start_j, end_j + 1):
                    sh_val = (sh_val + s_sol[j] * h_coeffs[k-j])
                
                diff = (sh_val - t[k]) % Q
                if diff > Q//2: diff -= Q
                tail_norm_sq += diff * diff
                
                if tail_norm_sq >= BOUND_CHECK**2:
                    possible = False
                    break
            
            if not possible:
                if attempt % 1000 == 0:
                    print(f"   Iter {attempt} s-Norm: {s_norm:.1f} (Checking...)", end='\r')
                continue

            # D. Success!
            tail_norm = np.sqrt(tail_norm_sq)
            print(f"\n[!] MATCH! s-Norm: {s_norm:.2f} | Tail-Norm: {tail_norm:.2f}")
            
            sig_str = "-----BEGIN NTRU SIGNATURE BLOCK-----\n"
            sig_str += "|".join(str(c) for c in s_sol)
            sig_str += "\n==" + str(r)
            sig_str += "\n-----END NTRU SIGNATURE BLOCK-----\n"
            current_sig = sig_str
            break

    # --- STEP 3: GET FLAG ---
    print("\n" + "="*30)
    flag = s.post(f"{URL}/flag").json()
    print("FLAG RESPONSE:", flag)
    print("="*30)

if __name__ == "__main__":
    solve_challenge()