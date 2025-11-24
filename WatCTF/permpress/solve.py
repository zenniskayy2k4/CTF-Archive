import sys
from pwn import *

# Implement the fnv1a_64 hash function used in the Rust code
def fnv1a_64(data):
    h = 0xcbf29ce484222325
    for byte in data:
        h ^= byte
        h = (h * 0x100000001b3) & 0xFFFFFFFFFFFFFFFF
    return h

def do_hash(x):
    return fnv1a_64(x.to_bytes(4, 'little', signed=True))

# Pre-compute hash buckets
HASH_SIZE = 32
buckets = [[] for _ in range(HASH_SIZE)]
for i in range(256):
    h = do_hash(i)
    buckets[h % HASH_SIZE].append(i)

# Connect to the server
# r = process(["cargo", "run", "--release"]) # For local testing
r = remote("challs.watctf.org", 2333)

def get_oracle_response(payload_str):
    r.sendlineafter(b"Enter your choice: ", b"1")
    r.sendlineafter(b"seperated by spaces: ", payload_str.encode())
    r.recvuntil(b"The oracle has divined... ")
    return int(r.recvline().strip())

# The final secret permutation
secret_perm = [-1] * 256

# Loop through all numbers from 0 to 255 to find their mapping
for k in range(256):
    if k % 10 == 0:
        print(f"[*] Solving for S[{k}]...")

    # Find the bucket for k
    k_bucket_idx = do_hash(k) % HASH_SIZE
    k_bucket = buckets[k_bucket_idx]

    # Find two different clobberers for k
    clobberer1 = -1
    clobberer2 = -1
    for item in k_bucket:
        if item != k:
            if clobberer1 == -1:
                clobberer1 = item
            else:
                clobberer2 = item
                break
    
    if clobberer1 == -1 or clobberer2 == -1:
        print(f"[!] Could not find two clobberers for {k}")
        sys.exit(1)

    # --- First run with clobberer1 ---
    perm1 = ([k, clobberer1] * 128)
    payload1 = " ".join(map(str, perm1))
    
    responses1 = set()
    # Query multiple times to ensure we get both possible outputs
    while len(responses1) < 2:
        responses1.add(get_oracle_response(payload1))

    # --- Second run with clobberer2 ---
    perm2 = ([k, clobberer2] * 128)
    payload2 = " ".join(map(str, perm2))

    responses2 = set()
    while len(responses2) < 2:
        responses2.add(get_oracle_response(payload2))
        
    # Find the intersection to reveal S[k]
    intersection = responses1.intersection(responses2)
    if len(intersection) != 1:
        print(f"[!] Error: Intersection for k={k} is not of size 1. Got {intersection}")
        # This can happen by chance if S[clobberer1] == S[clobberer2], try a third clobberer if needed.
        # But it's very unlikely.
        sys.exit(1)
        
    secret_perm[k] = intersection.pop()
    print(f"[*] Found S[{k}] = {secret_perm[k]}")

print("\n[+] Recovered the full secret permutation:")
print(secret_perm)

# Submit the final guess
final_payload = " ".join(map(str, secret_perm))
r.sendlineafter(b"Enter your choice: ", b"2")
r.sendlineafter(b"seperated by spaces: ", final_payload.encode())

# Print the flag
r.interactive()