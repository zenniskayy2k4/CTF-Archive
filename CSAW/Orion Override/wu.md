Chính xác! Chúc mừng bạn đã giải được bài CTF này. Dưới đây là bài viết hướng dẫn giải (write-up) chi tiết.

### Write-up: Orion Override - CSAW CTF

Bài CTF "Orion Override" thử thách người chơi tìm ra và khai thác một lỗ hổng logic trong cơ chế kiểm soát quyền truy cập của một ứng dụng web. Mục tiêu là giành được quyền quản trị viên (admin) để thực hiện một hành động đặc biệt và lấy được cờ (flag).

---

### Bước 1: Phân tích trang đăng nhập và tìm thông tin xác thực

Khi truy cập vào đường link `https://orion-override.ctf.csaw.io/`, chúng ta được dẫn đến một trang đăng nhập.

Hành động đầu tiên trong các bài CTF web là luôn kiểm tra mã nguồn của trang (`View Page Source` hoặc `Ctrl+U`). Trong mã nguồn HTML của trang đăng nhập, có một gợi ý rất rõ ràng do "thực tập sinh" để lại:

```html
<!-- the intern left a note on the wall, what could it be? -->
<!-- user:password -->
```

Gợi ý này cung cấp cho chúng ta thông tin đăng nhập:
*   **Username:** `user`
*   **Password:** `password`

### Bước 2: Đăng nhập và phân tích trang tổng quan (Dashboard)

Sử dụng thông tin đăng nhập trên, chúng ta đăng nhập thành công và được chuyển hướng đến trang tổng quan người dùng (User Dashboard).

Tại đây, chúng ta thấy các thông tin về nhiệm vụ nhưng các chức năng quan trọng như "Abort Mission" (Hủy bỏ nhiệm vụ) đều bị vô hiệu hóa với thông báo "You are not the admin".

Điểm mấu chốt ở bước này là quan sát thanh địa chỉ (URL) của trình duyệt. URL sau khi đăng nhập có dạng:

```
https://orion-override.ctf.csaw.io/dashboard?admin=false
```

Tham số `?admin=false` ngay lập tức gợi ý rằng ứng dụng có thể đang dựa vào tham số này trên URL để xác định quyền hạn của người dùng.

### Bước 3: Khai thác lỗ hổng Logic - HTTP Parameter Pollution (HPP)

Suy nghĩ đầu tiên của nhiều người là thử thay đổi `admin=false` thành `admin=true`. Tuy nhiên, trong trường hợp này, máy chủ có thể đã được cấu hình để bỏ qua hoặc từ chối thay đổi đơn giản này.

Đây là lúc chúng ta cần áp dụng một kỹ thuật nâng cao hơn một chút: **HTTP Parameter Pollution (HPP)**. Kỹ thuật này khai thác cách các công nghệ backend khác nhau xử lý các tham số có tên trùng lặp trong một yêu cầu HTTP. Ví dụ, khi nhận được URL `?name=John&name=Doe`, một số máy chủ sẽ lấy giá trị đầu tiên (`John`), một số lấy giá trị cuối cùng (`Doe`), và một số khác kết hợp chúng lại (`John, Doe`).

Trong bài này, ứng dụng có thể đang kiểm tra giá trị của tham số `admin` đầu tiên. Nếu nó là `false`, logic kiểm tra sẽ dừng lại. Tuy nhiên, nếu chúng ta "gây nhiễu" (pollute) URL bằng cách thêm một tham số `admin` nữa, chúng ta có thể bypass được cơ chế kiểm tra này.

Chúng ta sẽ thêm `&admin=true` vào cuối URL hiện tại:

**URL khai thác:**
```
https://orion-override.ctf.csaw.io/dashboard?admin=false&admin=true
```

Khi truy cập vào URL này, backend của ứng dụng có thể đã xử lý tham số `admin` cuối cùng (`true`) và cấp cho chúng ta quyền quản trị viên, mặc dù tham số đầu tiên là `false`.

### Bước 4: Giành quyền Admin và lấy Flag

Sau khi truy cập vào URL đã được sửa đổi, trang web tải lại và giao diện đã thay đổi. Các nút "Abort Mission", "Override Navigation", và "Override Life Support" không còn bị vô hiệu hóa nữa.

Chúng ta nhấp vào nút **"Abort Mission"**. Một thông báo (alert) sẽ hiện ra, chứa cờ (flag) của bài CTF.

>Flag: `csawctf{h7tpp0llut10n_0r10n_z8y7x6w5v4u3}`

---

### Kết luận

Lỗ hổng chính trong bài này là sự kết hợp giữa việc kiểm soát quyền truy cập không an toàn (dựa vào tham số phía client) và cách xử lý tham số lỏng lẻo của backend, cho phép khai thác bằng kỹ thuật HTTP Parameter Pollution. Đây là một ví dụ điển hình về "lỗi logic" (logic bug) trong phát triển web.