#!/usr/bin/env python3
from pwn import *
from z3 import *
import math

# --- Server details ---
HOST = "34.252.33.37"
PORT = 31764
KNOWN_PREFIX = b'BHFlagY{'
MODULUS = 2**64

def get_encrypted_flag(p):
    """Interacts with the server to get one encrypted flag."""
    p.sendlineafter(b'> ', b's')
    p.recvuntil(b'|   ~~~ ')
    line = p.recvline().strip()
    hex_flag = line.split(b' ')[0]
    return bytes.fromhex(hex_flag.decode())

def solve():
    p = remote(HOST, PORT)

    # 1. Get 3 ciphertexts
    log.info("Requesting 3 encrypted flags from the server...")
    c1 = get_encrypted_flag(p)
    c2 = get_encrypted_flag(p)
    c3 = get_encrypted_flag(p)
    p.close()
    log.success("Got 3 ciphertexts.")

    # 2. Determine 'l' and recover states
    l = math.ceil(len(c1) / 8)
    log.info(f"Ciphertext length is {len(c1)} bytes. Correct number of blocks 'l' is {l}.")

    s1_val = int.from_bytes(xor(c1[:8], KNOWN_PREFIX), 'big')
    s_l_plus_1_val = int.from_bytes(xor(c2[:8], KNOWN_PREFIX), 'big')
    s_2l_plus_1_val = int.from_bytes(xor(c3[:8], KNOWN_PREFIX), 'big')
    
    log.info(f"Recovered S_1 = {hex(s1_val)}")
    log.info(f"Recovered S_{l+1} = {hex(s_l_plus_1_val)}")
    log.info(f"Recovered S_{2*l+1} = {hex(s_2l_plus_1_val)}")

    # 3. Model the problem using Z3
    log.info("Modeling the LCG constraints for Z3 solver...")
    a = BitVec('a', 64)
    c = BitVec('c', 64)
    states = [BitVec(f's_{i}', 64) for i in range(2 * l + 2)]
    
    solver = Solver()
    solver.add(states[1] == s1_val)
    solver.add(states[l + 1] == s_l_plus_1_val)
    solver.add(states[2 * l + 1] == s_2l_plus_1_val)
    
    for i in range(1, 2 * l + 1):
        solver.add(states[i+1] == a * states[i] + c)
        
    solver.add(a & 7 == 5)
    solver.add(c & 1 == 1)
    
    # 4. Iterate through all possible solutions from Z3
    log.info("Solving for 'a' and 'c' and trying all possible solutions...")
    solution_count = 0
    while solver.check() == sat:
        solution_count += 1
        model = solver.model()
        a_sol = model[a].as_long()
        c_sol = model[c].as_long()
        
        log.info(f"Trying solution #{solution_count}: a={hex(a_sol)}, c={hex(c_sol)}")

        # 5. Reconstruct the keystream with the current solution
        otp_full = b''
        current_s = s1_val
        for _ in range(l):
            otp_full += current_s.to_bytes(8, 'big')
            current_s = (a_sol * current_s + c_sol) % MODULUS
            
        otp = otp_full[:len(c1)]
        
        # 6. Decrypt the flag and check if it's correct
        flag = xor(c1, otp)
        
        if flag.startswith(KNOWN_PREFIX) and flag.endswith(b'}'):
            log.success(f"FLAG FOUND: {flag.decode()}")
            return # Exit successfully
        else:
            log.warning(f"Solution #{solution_count} did not yield the flag.")
            # Add a constraint to exclude this solution and find the next one
            solver.add(Or(a != a_sol, c != c_sol))
    
    log.error("Could not find a valid flag after trying all solutions.")

if __name__ == "__main__":
    solve()