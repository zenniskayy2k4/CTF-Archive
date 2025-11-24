from pwn import *
from Crypto.Util.number import long_to_bytes, inverse
import ast

HOST = "amt.rs"
PORT = 38121

SAMPLE_COUNT = 400

def get_initial_data():
    conn = remote(HOST, PORT)
    line = conn.recvline().decode().strip()
    
    n_val, e_val = ast.literal_eval(line.replace('n, e = ', ''))
    
    log.info(f"n = {n_val}")
    log.info(f"e = {e_val}")
    
    return conn, n_val, e_val

def get_ciphertexts(conn, scramble_value, count):
    ciphertexts = []
    p = log.progress(f"Collecting {count} ciphertexts for scramble = {scramble_value}")
    for i in range(count):
        p.status(f"{i+1}/{count}")
        try:
            conn.sendlineafter(b'scramble the flag: ', str(scramble_value).encode())
            conn.recvline()
            c_line = conn.recvline().decode().strip()
            c_val = int(c_line.replace('c = ', ''))
            ciphertexts.append(c_val)
        except EOFError:
            log.error("Lost connection to the server. Please check HOST/PORT.")
            exit(1)
            
    p.success("Completed")
    return ciphertexts

def main():
    conn, n, e = get_initial_data()

    # Gửi scramble = 0
    c0_list = get_ciphertexts(conn, 0, SAMPLE_COUNT)
    
    # Gửi scramble = 1
    c1_list = get_ciphertexts(conn, 1, SAMPLE_COUNT)
    
    conn.close()
    
    found = False
    for i, c1 in enumerate(c1_list):
        print(f"\rTrying pair with c1[{i}/{len(c1_list)}]", end="")
        
        for c0 in c0_list:
            # Franklin-Reiter attack formula for e=3 and messages m, m+1
            # m = (c1 + 2*c0 - 1) * inverse(c1 - c0 + 2, n)
            try:
                numerator = (c1 + 2 * c0 - 1) % n
                denominator = (c1 - c0 + 2) % n
                
                inv_den = inverse(denominator, n)
                
                m = (numerator * inv_den) % n
                
                if pow(m, 3, n) == c0:
                    log.success("\nFound original message m!")
                    
                    # The original flag was left-shifted by 256 bits, so we right-shift by 256 bits to recover it
                    flag_long = m >> 256
                    flag = long_to_bytes(flag_long)
                    
                    log.success(f"Flag: {flag.decode()}")
                    found = True
                    break
            except ValueError:
                continue
        if found:
            break
            
    if not found:
        log.failure("Not found flag.")

if __name__ == "__main__":
    main()