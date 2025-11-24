#!/usr/bin/env python3
from pwn import *

D = 0xD3ADC0DE

def solve_round(r):
    r.recvuntil(b"--- Test #")
    r.recvline()
    n_line = r.recvline().strip()
    n = int(n_line.split(b" = ")[1])
    log.info(f"b.n = {n}")

    r.recvuntil(b"You can ask 7 questions:\n")

    # Prepare 7 queries for ternary search
    for i in range(7):
        group0 = []
        group1 = []
        group2 = [] # We need group2 now to pick a dummy value
        
        # Split all possible secrets into 3 groups based on their i-th ternary digit
        for secret_guess in range(2048):
            digit = (secret_guess // (3**i)) % 3
            if digit == 0:
                group0.append(secret_guess)
            elif digit == 1:
                group1.append(secret_guess)
            else:
                group2.append(secret_guess)
        
        # For each secret in a group, create the magic 'x' value
        query_li = [1 - (s + D) * n for s in group0]
        query_ri = [1 - (s + D) * n for s in group1]

        query_parts = query_li + query_ri
        
        # --- FIX STARTS HERE ---
        # If the total length is odd, the server will complain.
        # Add a dummy element to make it even.
        if len(query_parts) % 2 != 0:
            # Pick a secret from group2 to create a dummy value.
            # This won't interfere with our check for group0 and group1.
            dummy_secret = group2[0]
            dummy_val = 1 - (dummy_secret + D) * n
            query_parts.append(dummy_val)
        # --- FIX ENDS HERE ---

        # Send the query
        query_str = " ".join(map(str, query_parts))
        r.sendline(query_str.encode())

    # Receive the 7 result lines
    results = []
    for i in range(7):
        line = r.recvline().strip().split()
        res_L = int(line[0])
        res_R = int(line[1])
        results.append((res_L, res_R))

    # Determine the ternary digits
    ternary_digits = []
    for i in range(7):
        res_L, res_R = results[i]
        if res_L == 0:
            ternary_digits.append(0)
        elif res_R == 0:
            ternary_digits.append(1)
        else:
            ternary_digits.append(2)
    
    # Reconstruct the secret
    secret = 0
    for i in range(7):
        secret += ternary_digits[i] * (3**i)

    log.success(f"Found secret: {secret}")

    # Send the final guess
    r.recvuntil(b"Can you guess my secret?\n")
    r.sendline(str(secret).encode())

    # Check result
    response = r.recvline()
    log.info(response.decode().strip())
    if b"Correct!" not in response:
        log.error("Failed round!")
        r.interactive() # Drop to interactive to see what went wrong
        exit(1)


def main():
    # Make sure to replace with the correct host and port
    r = remote("0.cloud.chals.io", 32957)

    for i in range(10):
        log.info(f"--- Starting round {i} ---")
        solve_round(r)

    # Get the flag
    flag = r.recvall()
    log.success(f"Flag: {flag.decode()}")
    r.close()

if __name__ == "__main__":
    main()