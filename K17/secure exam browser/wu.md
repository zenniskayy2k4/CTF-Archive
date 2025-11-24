### Write-up: Secure Exam Browser - Reverse Engineering Challenge

### 1. Giới thiệu (Introduction)

**Secure Exam Browser** là một challenge Reverse Engineering (RE) yêu cầu tìm ra mật khẩu đúng để vượt qua bước xác thực. File thực thi là một ELF 64-bit cho Linux, được viết bằng C++ và có vẻ đã bị làm rối (obfuscated) cũng như tích hợp cơ chế chống gỡ lỗi (anti-debugging).

### 2. Phân tích ban đầu (Initial Analysis)

Khi chạy chương trình, nó yêu cầu nhập mật khẩu. Nhập sai sẽ nhận được thông báo "Incorrect password!".

```bash
$ ./secure_exam_browser
Welcome to Secure Exam Browser
Enter Password: test
Incorrect password!
```

Mở file bằng công cụ decompiler như Ghidra, chúng ta có thể thấy các hàm chính: `main`, `op`, và `(anonymous namespace)::decode_flag`.

#### 2.1. Phân tích hàm `main`

Hàm `main` có logic khá đơn giản:
1.  In thông điệp chào mừng.
2.  Đọc mật khẩu từ người dùng vào một biến `std::string`.
3.  Gọi hàm `decode_flag` để giải mã một chuỗi được mã hóa sẵn trong chương trình.
4.  So sánh mật khẩu người dùng nhập với chuỗi đã được giải mã.
5.  Nếu khớp, in ra "Integrity check complete!". Ngược lại, in "Incorrect password!".

=> **Mục tiêu:** Tìm ra chuỗi trả về của hàm `decode_flag`.

#### 2.2. Phân tích hàm `op`

Hàm `op` thực hiện một vòng lặp qua thư mục `/proc` để liệt kê tất cả các tiến trình đang chạy. Nó so sánh danh sách này với PID của chính nó (`getpid()`). Nếu phát hiện có bất kỳ tiến trình nào khác đang chạy, nó sẽ in ra "ERR: another process is running!" và thoát.

=> **Kết luận:** Đây là một cơ chế **anti-debugging** đơn giản. Khi chạy chương trình dưới một debugger (như GDB), GDB cũng là một tiến trình. Hàm `op` sẽ phát hiện GDB và tự kết thúc, ngăn cản việc gỡ lỗi.

#### 2.3. Phân tích hàm `decode_flag`

Hàm này cực kỳ phức tạp và bị làm rối nặng:
*   **Luồng điều khiển bị làm rối (Obfuscated Control Flow):** Sử dụng các cấu trúc `for_wrapper` và các đối tượng functor thay vì vòng lặp `for`/`while` thông thường.
*   **Sử dụng Exception Handling để trả về giá trị:** Thay vì dùng lệnh `return`, hàm này ném ra một ngoại lệ (`__cxa_throw`) chứa chuỗi kết quả. Luồng thực thi sau đó nhảy đến khối `catch` để xử lý và trả về giá trị cho `main`.

=> **Kết luận:** Việc phân tích tĩnh (đọc code) để tìm ra thuật toán giải mã là không khả thi. Phương pháp hiệu quả nhất là **phân tích động (dynamic analysis)**.

### 3. Vượt qua Anti-Debugging (Bypassing Anti-Debugging)

Để có thể gỡ lỗi chương trình, chúng ta cần vô hiệu hóa hàm `op`.
1.  Mở file `secure_exam_browser` trong Ghidra.
2.  Tìm đến hàm `op`.
3.  Trong cửa sổ Assembly, tìm đến địa chỉ bắt đầu của hàm (`0x103e67`).
4.  Sử dụng tính năng "Patch Instruction" (`Ctrl+Shift+G`) để ghi đè lên các lệnh đầu tiên của hàm.
    *   Tại `0x103e67`, patch lệnh thành `MOV EAX, 1`. Lệnh này đặt giá trị trả về của hàm là `1` (thành công).
    *   Tại dòng tiếp theo, patch lệnh thành `RET`. Lệnh này khiến hàm kết thúc ngay lập tức.
5.  Xuất file đã được patch ra một file mới, ví dụ `secure_exam_browser_patched`, và cấp quyền thực thi (`chmod +x`).

File mới này giờ đã có thể được gỡ lỗi mà không bị thoát đột ngột.

### 4. Tìm Flag bằng Gỡ lỗi (Finding the Flag via Debugging)

Chúng ta sẽ sử dụng GDB để chạy file đã patch và tìm mật khẩu.

#### 4.1. Xử lý PIE (Position Independent Executable)

File thực thi này được biên dịch với PIE, nghĩa là địa chỉ của nó sẽ bị ngẫu nhiên hóa mỗi lần chạy. Để đặt breakpoint chính xác, chúng ta cần tính toán địa chỉ thực tế trong bộ nhớ dựa trên địa chỉ cơ sở (base address) ngẫu nhiên.

#### 4.2. Các bước thực hiện trong GDB

1.  Mở file đã patch trong GDB:
    ```bash
    gdb ./secure_exam_browser_patched
    ```

2.  Sử dụng lệnh `start` để chạy chương trình và dừng lại ngay tại điểm bắt đầu. Lệnh này cho phép chương trình được nạp vào bộ nhớ và chúng ta có thể xác định địa chỉ cơ sở của nó.
    ```gdb
    start
    ```

3.  GDB (với plugin GEF) sẽ dừng lại và hiển thị thông tin. Chúng ta cần tìm địa chỉ cơ sở. Dựa vào địa chỉ của hàm `_start` mà GDB dừng lại (ví dụ: `0x555555557580`) và địa chỉ offset của `_start` trong Ghidra (`0x103580`), ta tính được địa chỉ cơ sở:
    `Base Address = Địa chỉ thực tế của _start - Offset của _start`
    `Base Address = 0x555555557580 - 0x103580 = 0x555555454000`
    *(Lưu ý: Địa chỉ cơ sở này sẽ thay đổi mỗi lần bạn chạy)*

4.  Bây giờ, chúng ta tính địa chỉ breakpoint thực tế. Trong Ghidra, điểm dừng lý tưởng là `0x104da5`.
    `Địa chỉ Breakpoint = Base Address + Offset`
    `Địa chỉ Breakpoint = 0x555555454000 + 0x104da5 = 0x555555558da5`

5.  Đặt breakpoint tại địa chỉ vừa tính được:
    ```gdb
    b *0x555555558da5
    ```

6.  Tiếp tục chạy chương trình:
    ```gdb
    continue
    ```

7.  Khi được yêu cầu, nhập một mật khẩu bất kỳ (ví dụ: `flag`). Chương trình sẽ dừng lại tại breakpoint.

8.  Tại thời điểm này, theo quy ước gọi hàm x86-64, con trỏ đến chuỗi ký tự đã được giải mã được truyền vào hàm thông qua thanh ghi `RSI`. Chúng ta chỉ cần kiểm tra nội dung tại địa chỉ mà `RSI` đang trỏ tới:
    ```gdb
    x/s $rsi
    ```

9.  GDB sẽ hiển thị kết quả:
    ```
    0x555555570ba0: "K17{i_heard_that_it's_impossible_to_re_c++!}*"
    ```

### 5. Kết luận (Conclusion)

Chúng ta đã tìm thấy mật khẩu. Chạy lại chương trình gốc và nhập chuỗi này vào để xác nhận.

```bash
$ ./secure_exam_browser
Welcome to Secure Exam Browser
Enter Password: K17{i_heard_that_it's_impossible_to_re_c++!}
Integrity check complete!
No exams available. Exiting.
```

**Flag:** `K17{i_heard_that_it's_impossible_to_re_c++!}`