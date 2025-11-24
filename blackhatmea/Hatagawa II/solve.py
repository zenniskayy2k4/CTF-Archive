#!/usr/bin/env python3
from pwn import *
from z3 import *
import math

# --- Server details ---
HOST = "34.252.33.37"
PORT = 30125

def parse_flag_ciphertext(full_flag_bytes):
    """Strips 'BHFlagY{}' and hex-decodes the content."""
    prefix = b'BHFlagY{'
    suffix = b'}'
    if not full_flag_bytes.startswith(prefix) or not full_flag_bytes.endswith(suffix):
        raise ValueError("Invalid flag format received")
    
    hex_content = full_flag_bytes[len(prefix):-len(suffix)]
    return bytes.fromhex(hex_content.decode())

def solve():
    # 1. Get THREE ciphertexts
    log.info("Requesting 3 encrypted flags from the server...")
    with remote(HOST, PORT) as p:
        p.sendlineafter(b'> ', b's')
        p.recvuntil(b'|   ~~~     ')
        full_c1 = p.recvline().strip().split(b' ')[0]

        p.sendlineafter(b'> ', b's')
        p.recvuntil(b'|   ~~~     ')
        full_c2 = p.recvline().strip().split(b' ')[0]
        
        p.sendlineafter(b'> ', b's')
        p.recvuntil(b'|   ~~~     ')
        full_c3 = p.recvline().strip().split(b' ')[0]
    log.success("Got 3 full ciphertexts.")
    
    # 2. Parse ciphertexts and calculate XOR differences
    c1_raw = parse_flag_ciphertext(full_c1)
    c2_raw = parse_flag_ciphertext(full_c2)
    c3_raw = parse_flag_ciphertext(full_c3)
    
    k = len(c1_raw)
    
    # CORE LOGIC: The loop condition is `while len(otp) <= len(msg):`
    l_generated = math.ceil(k / 8)
    if k > 0 and k % 8 == 0:
        l_generated += 1
    
    l = l_generated
    log.info(f"Plaintext length is {k} bytes. Server generates {l} blocks per encryption.")
    
    k_diff12 = xor(c1_raw, c2_raw)
    k_diff23 = xor(c2_raw, c3_raw)
    
    D1 = int.from_bytes(k_diff12[:8], 'big') # S_1 ^ S_{l+1}
    D2 = int.from_bytes(k_diff23[:8], 'big') # S_{l+1} ^ S_{2l+1}

    # 3. Model the problem using Z3
    log.info("Modeling the LCG constraints for Z3 solver...")
    a = BitVec('a', 64)
    c = BitVec('c', 64)
    s1 = BitVec('s1', 64)
    s_l_plus_1 = BitVec('s_l_plus_1', 64)
    s_2l_plus_1 = BitVec('s_2l_plus_1', 64)
    
    solver = Solver()

    solver.add(s1 ^ s_l_plus_1 == D1)
    solver.add(s_l_plus_1 ^ s_2l_plus_1 == D2)
    
    def lcg_l_steps(start_state, num_steps, a, c):
        state = start_state
        for _ in range(num_steps):
            state = a * state + c
        return state

    solver.add(s_l_plus_1 == lcg_l_steps(s1, l, a, c))
    solver.add(s_2l_plus_1 == lcg_l_steps(s_l_plus_1, l, a, c))
    
    solver.add(a & 7 == 5)
    solver.add(c & 1 == 1)
    
    # 4. Find ALL possible solutions and collect them
    log.info("Solving for parameters and finding ALL possible flags...")
    solution_count = 0
    MODULUS = 2**64
    candidate_flags = []
    
    while solver.check() == sat:
        solution_count += 1
        model = solver.model()
        a_sol = model[a].as_long()
        c_sol = model[c].as_long()
        s1_sol = model[s1].as_long()
        
        log.info(f"Found solution #{solution_count}: a={hex(a_sol)}, c={hex(c_sol)}, s1={hex(s1_sol)}")

        l_used = math.ceil(k/8)
        otp_full = b''
        current_s = s1_sol
        for _ in range(l_used):
            otp_full += current_s.to_bytes(8, 'big')
            current_s = (a_sol * current_s + c_sol) % MODULUS
        
        otp = otp_full[:k]
        
        plaintext = xor(c1_raw, otp)
        flag = f"BHFlagY{{{plaintext.hex()}}}"
        candidate_flags.append(flag)

        # Exclude this solution and find the next one
        solver.add(Or(a != a_sol, c != c_sol, s1 != s1_sol))
    
    if not candidate_flags:
        log.error("Could not find any solution.")
    else:
        log.success(f"Found {len(candidate_flags)} possible flag(s). Please try submitting them:")
        print("\n" + "="*50)
        for i, flag in enumerate(candidate_flags):
            print(f"Candidate #{i+1}: {flag}")
        print("="*50 + "\n")

if __name__ == "__main__":
    solve()