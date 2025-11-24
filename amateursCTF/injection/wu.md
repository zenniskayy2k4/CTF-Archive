# Write-up: AmateursCTF - Injection
**Category:** Pwn / Sandbox / Linux Internals
**Difficulty:** Hard

## 1. Phân tích bài toán (Reconnaissance)

Đầu tiên, chúng ta được cung cấp mã nguồn `chal.c` và các script cấu hình môi trường (Dockerfile, run.sh). Hãy xem điều gì đang diễn ra.

### Phân tích `chal.c`
Chương trình thực hiện các bước sau:
1.  **Đọc flag thật** từ `/tmp/flag` vào bộ nhớ (biến `flag` nằm trên Stack).
2.  **Xóa flag thật**: Nó mở lại file `/tmp/flag` và ghi đè bằng nội dung giả (`fake_flag`).
    *   => *Điều này có nghĩa là ta không thể đọc flag từ file trên đĩa được nữa. Flag chỉ còn tồn tại trong RAM (Stack) của tiến trình cha.*
3.  **Nhận input từ người dùng**: Nó hỏi kích thước và đọc một đoạn dữ liệu (ELF binary) mà ta gửi lên, lưu vào `/tmp/solve`.
4.  **Fork (Tạo tiến trình con)**:
    *   **Tiến trình Cha (Parent):** Đi vào vòng lặp vô tận `while(true) { sleep(1); }`. Lưu ý: Flag vẫn nằm trong RAM của ông bố này.
    *   **Tiến trình Con (Child):**
        *   Cài đặt **Seccomp** (Bộ lọc System Call).
        *   Thực thi file `/tmp/solve` mà ta vừa gửi lên (`execve`).

### Môi trường Sandbox (Nhà tù)
Điều khiến bài này khó chính là cấu hình **Seccomp** trong hàm `install_seccomp`. Nó chỉ cho phép đúng 6 system call (syscall):
1.  `read` (0)
2.  `write` (1)
3.  `open` (2) - Lưu ý: Chỉ `open`, không phải `openat`.
4.  `execve` (59)
5.  `exit` (60)
6.  `exit_group` (231)

**Hậu quả:**
*   Các lệnh shell bình thường (`ls`, `cat`) sẽ chết ngay lập tức vì chúng cần nhiều syscall khác (`getdents`, `fstat`, `mmap`...).
*   Thư viện chuẩn C (`libc`) thông thường cũng không chạy được vì hàm `printf`, `fopen` cần các syscall bị cấm.
*   **Quan trọng:** Syscall `lseek` bị chặn. Điều này ngăn cản việc chúng ta đọc bộ nhớ tùy ý thông qua `/proc/pid/mem` theo cách thông thường.

## 2. Ý tưởng tấn công (Attack Vector)

Mục tiêu: Đọc nội dung Stack của **Tiến trình Cha**.

### Các cách tiếp cận thất bại:
1.  **Chạy Shellcode/Binary thông thường:** Bị Seccomp giết.
2.  **Đọc `/proc/$ppid/mem`:** Để đọc mem, ta cần `lseek` đến địa chỉ hợp lệ. Nhưng `lseek` bị chặn.
3.  **Đọc `/proc/$ppid/map_files/`:** Một kỹ thuật để bypass `lseek`, nhưng trong môi trường này thư mục `/proc` có vẻ bị hạn chế hoặc mount không đầy đủ.

### Cách tiếp cận thành công: Libc Poisoning (Đầu độc thư viện)

Ta nhận thấy trong file `run.sh`:
```bash
cp /lib/x86_64-linux-gnu/libc.so.6 /tmp
cd /tmp
/app/chal
```
File thư viện `libc.so.6` được copy vào `/tmp`. Tiến trình cha (`chal`) đang chạy và load thư viện này từ `/tmp`.
*   **Điểm yếu:** `/tmp` là thư mục mà ta (người dùng/tiến trình con) có quyền **Ghi**.
*   **Cơ chế Linux:** Khi một file thư viện (`.so`) đang được một tiến trình sử dụng, nếu ta mở file đó và ghi đè nội dung lên nó, hệ điều hành (thông qua Page Cache) có thể cập nhật thay đổi đó cho tiến trình đang chạy.

**Kịch bản tấn công:**
1.  Viết một chương trình exploit "sạch" (không dùng libc chuẩn) để lọt qua Seccomp.
2.  Chương trình này sẽ mở file `/tmp/libc.so.6`.
3.  Tìm hàm `sleep` trong file đó. (Vì bố đang gọi `sleep(1)` liên tục).
4.  Ghi đè code của hàm `sleep` bằng **Shellcode** của chúng ta.
5.  Khi bố gọi `sleep` lần tới, bố sẽ chạy Shellcode thay vì ngủ.
6.  Shellcode sẽ thực hiện: `write(stdout, stack_pointer, ...)` để in flag ra cho chúng ta.

## 3. Chi tiết kỹ thuật Exploit

### Bước 1: Viết code "Nostdlib" (Không thư viện chuẩn)
Vì Seccomp quá gắt, ta không thể dùng `gcc exploit.c` bình thường. Ta phải dùng cờ `-nostdlib` và tự định nghĩa các syscall bằng Assembly.

Ví dụ hàm `my_write` thay cho `write` của C:
```c
long my_write(int fd, const void *buf, unsigned long count) {
    long ret;
    // Gọi syscall số 1 (write) trực tiếp
    asm volatile ("syscall" : "=a"(ret) : "a"(1), "D"(fd), "S"(buf), "d"(count) : "memory");
    return ret;
}
```

### Bước 2: Tìm vị trí hàm `sleep` trong ELF
File `libc.so.6` là định dạng ELF. Ta phải parse (phân tích) nó thủ công trong code C:
1.  Đọc Header ELF.
2.  Tìm Section Header.
3.  Tìm bảng Symbol (`.dynsym`) và bảng chuỗi (`.dynstr`).
4.  Duyệt qua các symbol, so sánh tên với chuỗi "sleep".
5.  Lấy địa chỉ offset của hàm `sleep`.

### Bước 3: Kỹ thuật NOP Sled (Cầu trượt)
Đây là phần tinh tế nhất.
*   Tiến trình cha đang ngủ (`nanosleep` syscall).
*   Khi nó tỉnh dậy, CPU sẽ quay về một địa chỉ nằm **giữa** hàm `sleep` (địa chỉ return sau syscall).
*   Nếu ta ghi đè Shellcode ngay đầu hàm `sleep`, khi cha tỉnh dậy, cha sẽ rơi vào giữa đống code của ta -> **Crash** (Segmentation Fault).

**Giải pháp:** Dùng NOP Sled.
*   **NOP** (`0x90`) là lệnh Assembly "No Operation" (Không làm gì cả, đi tiếp lệnh sau).
*   Ta ghi đè 200 byte đầu của hàm `sleep` bằng toàn `0x90`.
*   Ta đặt Shellcode ở **cuối** 200 byte đó.
*   **Kết quả:** Dù cha tỉnh dậy ở bất cứ đâu trong vùng 200 byte này, CPU sẽ trượt (slide) qua các lệnh NOP cho đến khi chạm vào Shellcode ở cuối. -> **Thành công 100%**.

### Bước 4: Shellcode lấy Flag
Shellcode (viết bằng Assembly) sẽ làm nhiệm vụ đơn giản: In nội dung Stack ra màn hình.
```asm
mov rdi, 1          ; File descriptor 1 (stdout)
mov rsi, rsp        ; Buffer = Stack Pointer (nơi chứa flag)
mov rdx, 0x10000    ; Độ dài = 64KB (đủ lớn để bao trùm flag)
mov rax, 1          ; Syscall Write
syscall
```

## 4. Code giải thích (Snippet)

Đây là đoạn code quan trọng nhất trong file `solve.c`:

```c
    // ... (Sau khi đã tìm được offset của hàm sleep) ...

    // Tạo NOP Sled (Cầu trượt)
    // Ghi 200 byte toàn lệnh NOP (0x90)
    int patch_size = 200; 
    for (int i = 0; i < patch_size; i++) {
        libc_buf[sleep_offset + i] = 0x90;
    }

    // Đặt Shellcode vào cuối cầu trượt
    int start_shellcode = patch_size - sizeof(shellcode);
    for (int i = 0; i < sizeof(shellcode); i++) {
        libc_buf[sleep_offset + start_shellcode + i] = shellcode[i];
    }

    // Mở lại file libc để GHI ĐÈ
    // Lưu ý: Dùng O_WRONLY (1) chứ không dùng cờ tạo file mới
    int fd_out = my_open("/tmp/libc.so.6", O_WRONLY, 0);
    
    // Ghi toàn bộ buffer đã chỉnh sửa vào file
    // Linux sẽ cập nhật nội dung này vào bộ nhớ của tiến trình Cha ngay lập tức
    // nhờ cơ chế Page Cache và mmap.
    my_write(fd_out, libc_buf, total_read);
```

## 5. Kết luận

Để giải bài này, ta đã đi qua các kiến thức:
1.  **Seccomp:** Hiểu cách hệ điều hành chặn syscall và cách viết code bypass bằng assembly thuần.
2.  **Linux File System:** Hiểu rằng `/tmp/libc.so.6` có thể bị ghi đè bởi user.
3.  **ELF Parsing:** Tự phân tích cấu trúc file thực thi để tìm địa chỉ hàm.
4.  **Race Condition / Code Injection:** Lợi dụng lúc tiến trình khác đang chạy để thay đổi mã nguồn của nó (Hot patching).
5.  **NOP Sled:** Kỹ thuật kinh điển trong khai thác lỗi bộ nhớ đệm để tăng độ ổn định của exploit.

Đây là một bài học tuyệt vời về việc "Khi cửa chính (`ptrace`, `mem`) bị khóa, hãy tìm cửa sổ (`shared library injection`)".