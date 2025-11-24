#!/usr/bin/env python3
import sys
import time
import string
import base64
import re
import threading
from pwn import *
import bcrypt

# Set logging to info to see progress
context.log_level = 'info'

# Challenge configuration
HOST = '18.212.136.134'
PORT = 6666
STATIC_SALT = b"$2b$12$C8YQMlqDyz3vGN9VOGBeGu"
CHARSET = string.ascii_letters + string.digits

def brute_force_level1(leaked_part, expected_digest):
    """
    Level 1 requires us to match the hash of the secret.
    We know the first 70 bytes (leaked_part).
    Bcrypt only hashes the first 72 bytes.
    We just need to brute-force the missing 2 bytes (indices 70 and 71).
    """
    log.info("Brute-forcing missing 2 characters (this may take 1-2 minutes)...")
    
    found_suffix = None
    stop_event = threading.Event()
    
    def worker(chars_subset):
        nonlocal found_suffix
        for c1 in chars_subset:
            if stop_event.is_set(): return
            for c2 in CHARSET:
                if stop_event.is_set(): return
                
                # Construct candidate: Leaked part + guess
                candidate = leaked_part + c1 + c2
                
                # Bcrypt will truncate this to 72 bytes internally
                try:
                    res = bcrypt.hashpw(candidate.encode(), STATIC_SALT)
                    if res == expected_digest:
                        found_suffix = c1 + c2
                        stop_event.set()
                        return
                except Exception:
                    continue

    # Multithreading to speed up bcrypt (it releases GIL)
    threads = []
    n_threads = 10
    chunk_size = len(CHARSET) // n_threads + 1
    
    for i in range(0, len(CHARSET), chunk_size):
        subset = CHARSET[i:i+chunk_size]
        t = threading.Thread(target=worker, args=(subset,))
        t.start()
        threads.append(t)
        
    for t in threads:
        t.join()
    
    if found_suffix:
        return leaked_part + found_suffix
    return None

def solve():
    conn = remote(HOST, PORT)

    # -------------------------------------------------------------------------
    # LEVEL 1: The Lobby
    # -------------------------------------------------------------------------
    log.info("--- Level 1 ---")
    conn.recvuntil(b"Leaked Note: ")
    leaked_part = conn.recvline().strip().decode()
    conn.recvuntil(b"Target Hash: ")
    target_hash = conn.recvline().strip().decode()
    
    # Extract the raw bcrypt digest from the custom format: vb$1$<base64>
    b64_part = target_hash.split('$')[2]
    expected_digest = base64.b64decode(b64_part)
    
    password = brute_force_level1(leaked_part, expected_digest)
    
    if not password:
        log.error("Failed to crack Level 1.")
        return

    log.success(f"Found Level 1 password: {password}")
    conn.sendlineafter(b"Enter password: ", password.encode())

    # -------------------------------------------------------------------------
    # LEVEL 2: The Teller
    # -------------------------------------------------------------------------
    log.info("--- Level 2 ---")
    conn.recvuntil(b"prefix: '")
    prefix = conn.recvuntil(b"'", drop=True).decode()
    
    # Vulnerability: portion = payload[: len % 256]
    # If len % 256 == 0, portion is empty string b''.
    # We send two different strings with length 256. Both hash to bcrypt(b'').
    
    pad_len = 256 - len(prefix)
    s1 = prefix + "A" * pad_len
    s2 = prefix + "B" * pad_len
    
    conn.sendlineafter(b"Format: string1,string2", f"{s1},{s2}".encode())

    # -------------------------------------------------------------------------
    # LEVEL 3: The Manager's Office
    # -------------------------------------------------------------------------
    log.info("--- Level 3 ---")
    conn.recvuntil(b"very long (")
    target_len = int(conn.recvuntil(b" ", drop=True).decode())
    
    # Target is "B" * target_len.
    # Its hash uses portion: ("B" * target_len)[: target_len % 256]
    # We can just send that portion directly!
    # The length will be (target_len % 256), which is != target_len.
    
    k = target_len % 256
    payload = "B" * k
    conn.sendlineafter(b"equivalent password: ", payload.encode())

    # -------------------------------------------------------------------------
    # LEVEL 4: The Server Room
    # -------------------------------------------------------------------------
    log.info("--- Level 4 ---")
    prompt = conn.recvuntil(b"Enter password: ").decode()
    
    # Parse the target structure
    match = re.search(r"(\d+) 'C's \+ (\d+) '🔥'", prompt)
    pad_len = int(match.group(1))
    emoji_count = int(match.group(2))
    
    # Bcrypt ignores everything after byte 72.
    # We construct the target string, encode it, truncate to 72 bytes, and send it.
    full_target = "C" * pad_len + "🔥" * emoji_count
    full_bytes = full_target.encode('utf-8')
    
    # Calculate the effective password seen by bcrypt
    solution_bytes = full_bytes[:72]
    solution = solution_bytes.decode('utf-8')
    
    conn.sendline(solution.encode())

    # -------------------------------------------------------------------------
    # LEVEL 5: The Vault Door
    # -------------------------------------------------------------------------
    log.info("--- Level 5 ---")
    conn.recvuntil(b"Total Length = ")
    total_len = int(conn.recvuntil(b" bytes", drop=True).decode())
    
    # We need to authenticate as admin.
    # Admin input is: PREFIX + "X" * admin_pw_len
    # We are given the Total Length.
    # So admin_pw_len = Total Length - len(PREFIX)
    # If we send exactly "X" * admin_pw_len, our input is identical to admin's.
    
    prefix_len = 17 # "XCORP_VAULT_ADMIN"
    admin_pw_len = total_len - prefix_len
    payload = "X" * admin_pw_len
    
    conn.sendlineafter(b"Input your password:", payload.encode())

    # -------------------------------------------------------------------------
    # Victory
    # -------------------------------------------------------------------------
    conn.interactive()

if __name__ == "__main__":
    solve()