# a.py
from sage.all import *

def parse_public_txt(filepath="public.txt"):
    with open(filepath, 'r') as f:
        content = f.read()

    samples = []
    flag_data = {}

    blocks = content.split('BEGIN ')[1:]
    for block in blocks:
        lines = block.strip().split('\n')
        block_type = lines[0].split()[0]
        
        data = {}
        
        # Find where L starts and ends
        l_start_index = -1
        p_index = -1
        c_index = -1

        for i, line in enumerate(lines):
            if line.startswith('L:'):
                l_start_index = i + 1
            if line.startswith('P='):
                p_index = i
            if line.startswith('C='):
                c_index = i

        l_hex_rows = lines[l_start_index : p_index if p_index != -1 else c_index]
        c_hex = lines[c_index].split('=')[1]

        data['L_hex'] = l_hex_rows
        data['C_hex'] = c_hex

        if block_type == 'SAMPLE':
            samples.append(data)
        elif block_type == 'FLAG':
            flag_data = data
            
    return samples, flag_data

def hex_to_bits(hex_str):
    return list(map(int, bin(int(hex_str, 16))[2:].zfill(len(hex_str) * 4)))

def bits_to_bytes(bits):
    s = ''.join(map(str, bits))
    return int(s, 2).to_bytes((len(s) + 7) // 8, byteorder='big')

def main():
    N = 31
    D = N * (N + 1) // 2 + 1
    assert D == 497

    print("[+] Parsing public.txt...")
    samples, flag_data = parse_public_txt()
    print(f"[+] Found {len(samples)} samples and 1 flag block.")

    # Build the linear system A*z = b over GF(2)
    A_rows = []
    b_vec = []
    
    print("[+] Building the system of linear equations...")
    for sample in samples:
        # L is given as D rows, each row is a hex string representing a row vector of 512 bits.
        # This means L is a 497x512 matrix.
        # The equation is C = L^T * z
        # C (512x1), L^T (512x497), z (497x1)
        # This gives 512 linear equations per sample.
        
        L_rows_bits = [hex_to_bits(h) for h in sample['L_hex']]
        C_bits = hex_to_bits(sample['C_hex'])
        
        # Transpose L to get 512 rows, each of length 497
        L_T_rows = list(zip(*L_rows_bits))
        
        for i in range(len(L_T_rows)):
            A_rows.append(L_T_rows[i])
            b_vec.append(C_bits[i])

    print(f"[+] System built: {len(A_rows)} equations, {D} unknowns.")
    
    # Solve using SageMath
    print("[+] Solving the system over GF(2) using SageMath...")
    F = GF(2)
    A = Matrix(F, A_rows)
    b = vector(F, b_vec)
    
    # solve_right finds x such that Ax = b
    z_solution = A.solve_right(b)
    
    print("[+] System solved. Found secret vector z.")
    
    # --- Verification (Optional but good practice) ---
    # Recover t from z
    t_secret_recovered = list(z_solution[1:N+1])
    
    # Check if z matches the quadratic expansion of t
    def expand_t(t_vec):
        n = len(t_vec)
        res = [1]
        res.extend(t_vec)
        for i in range(n):
            for j in range(i + 1, n):
                res.append(t_vec[i] * t_vec[j])
        return vector(F, res)

    z_reconstructed = expand_t(t_secret_recovered)
    if z_reconstructed == z_solution:
        print("[+] Verification successful: z is the correct quadratic expansion of t.")
        print(f"    Recovered t_secret: {''.join(map(str, t_secret_recovered))}")
    else:
        print("[!] Verification FAILED. Something is wrong.")
        return

    # --- Decrypt the Flag ---
    print("[+] Decrypting the flag...")
    
    L_flag_rows_bits = [hex_to_bits(h) for h in flag_data['L_hex']]
    C_flag_bits = vector(F, hex_to_bits(flag_data['C_hex']))

    L_flag_T = Matrix(F, list(zip(*L_flag_rows_bits)))
    
    # Keystream = L_flag^T * z
    keystream = L_flag_T * z_solution
    
    # Plaintext = Ciphertext XOR Keystream
    P_flag_bits = C_flag_bits + keystream # In GF(2), addition is XOR
    
    flag_bytes = bits_to_bytes(list(P_flag_bits))
    
    try:
        print(f"\n[+] FLAG: {flag_bytes.decode('utf-8')}")
    except UnicodeDecodeError:
        print(f"\n[+] Recovered plaintext (raw bytes): {flag_bytes}")

if __name__ == '__main__':
    main()