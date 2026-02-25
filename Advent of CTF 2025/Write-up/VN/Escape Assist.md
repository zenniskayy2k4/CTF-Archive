# Write up

## Escape Assist

**Danh mục:** Crypto / Coding
**Mục tiêu:** Tìm số nguyên `n` thỏa mãn các điều kiện đồng dư phức tạp để kích hoạt lỗ hổng `eval()` và đọc cờ.

### 1. Phân tích source code

Thử thách cung cấp một server chạy đoạn code Python với các đặc điểm sau:

1.  **Tạo khóa:** Server sinh ra 42 số nguyên tố ngẫu nhiên `ps` (độ dài 26-bit).
2.  **Tính N:** $N$ là tích của tất cả 42 số nguyên tố này ($N = \prod p_i$).
3.  **Điều kiện kiểm tra:** Người dùng gửi số nguyên `n`. Server kiểm tra:
    *   $0 \le n < N$
    *   Với **mọi** số nguyên tố $p_i$, số dư $n \pmod{p_i}$ phải thuộc tập hợp `goods`.
4.  **Tập hợp `goods`:** Code định nghĩa `goods = [6, 7, -1, 13]`.
    *   Tuy nhiên, mô tả bài thi có gợi ý: *"turned the jail into 6 7"* (biến nhà tù thành 6 7).
    *   Đây là gợi ý quan trọng để giới hạn không gian tìm kiếm chỉ còn `{6, 7}`.
5.  **Lỗ hổng:** Nếu vượt qua kiểm tra, server chạy `print(eval(long_to_bytes(n)))`.

### 2. Ý tưởng khai thác

Mục tiêu của chúng ta là tạo ra một payload `n` sao cho:
1.  `long_to_bytes(n)` là một đoạn mã Python hợp lệ để in ra cờ.
2.  $n \pmod{p_i} \in \{6, 7\}$ với mọi $p_i$.

#### Vấn đề 1: Payload là gì?
Chúng ta cần in biến `flag`. Payload đơn giản nhất là chuỗi `flag`.
Tuy nhiên, số `n` được tạo ra từ toán học sẽ rất lớn (khoảng 130 bytes). 4 byte đầu là `flag`, còn hơn 100 byte sau sẽ là "rác" ngẫu nhiên do tính chất của phép toán.
Để Python không báo lỗi cú pháp vì phần rác này, ta dùng ký tự `#` (comment).
-> **Payload mục tiêu:** `b'flag#'` (phần sau `#` sẽ bị Python bỏ qua).

#### Vấn đề 2: "Rác" độc hại
Mặc dù `#` giúp bỏ qua rác, nhưng nếu trong phần rác vô tình xuất hiện ký tự xuống dòng (`\n` - byte 10 hoặc `\r` - byte 13), Python sẽ coi là hết dòng comment và cố thực thi phần rác tiếp theo -> Gây lỗi **SyntaxError**.
-> **Yêu cầu phụ:** Số `n` tìm được không được chứa byte `10` hoặc `13`.

#### Vấn đề 3: Toán học (Định lý số dư Trung Hoa - CRT)
Chúng ta cần tìm $n$ sao cho:
$$
\begin{cases}
n \equiv r_1 \pmod{p_1} \\
n \equiv r_2 \pmod{p_2} \\
\dots \\
n \equiv r_{42} \pmod{p_{42}}
\end{cases}
$$
Trong đó $r_i$ chỉ được chọn từ $\{6, 7\}$.
Tổng số trường hợp là $2^{42}$ (khoảng 4.4 nghìn tỷ). Đây là một con số quá lớn để thử hết (Brute-force), nhưng đủ nhỏ để dùng thuật toán thông minh hơn.

### 3. Thuật toán giải quyết: Meet-in-the-Middle (MITM)

Để tìm ra bộ $r_i$ sao cho $n$ bắt đầu bằng `flag#`, ta dùng kỹ thuật **Meet-in-the-Middle** (Gặp nhau ở giữa):

1.  **Chia đôi:** Chia 42 số nguyên tố thành 2 nhóm:
    *   Nhóm Trái (Left): 21 số đầu.
    *   Nhóm Phải (Right): 21 số sau.
    *   Độ phức tạp giảm từ $2^{42}$ xuống $2 \times 2^{21}$ (khoảng 2 triệu phép tính mỗi bên - rất nhanh).

2.  **Tính toán CRT từng phần:**
    *   Tính trọng số CRT `weights[i]` cho mỗi vị trí.
    *   Tính tất cả các tổng CRT có thể cho nhóm Trái và lưu vào danh sách `L`.
    *   Tính tất cả các tổng CRT có thể cho nhóm Phải và lưu vào danh sách `R`.

3.  **Tìm kiếm ghép cặp:**
    *   Sắp xếp danh sách `L` để tìm kiếm nhanh (Binary Search).
    *   Duyệt qua từng giá trị `r` trong danh sách `R`.
    *   Ta cần tìm `l` trong danh sách `L` sao cho:
        $(l + r) \pmod N \approx \text{Target (flag\#...)}$
    *   Cụ thể, tổng $(l+r)$ phải nằm trong khoảng $[\text{flag\#00...00}, \text{flag\#FF...FF}]$.

4.  **Kiểm tra điều kiện cuối:**
    *   Khi tìm được cặp `(l, r)` thỏa mãn khoảng giá trị, ta tính `n = (l + r) % N`.
    *   Chuyển `n` sang bytes và kiểm tra xem có chứa `\n` hay `\r` không. Nếu không -> **Thành công!**

### 4. Mã nguồn khai thác (SageMath)

Đây là đoạn code đã giúp bạn lấy cờ:

```python
import socket
from bisect import bisect_left
from Crypto.Util.number import long_to_bytes, bytes_to_long

HOST = 'ctf.csd.lol'
PORT = 5000
PAYLOAD = b'flag#' 

def attempt_solve(attempt_count):
    # 1. Kết nối và nhận 42 số nguyên tố
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))
    # ... (Code nhận dữ liệu primes) ...

    # 2. Chuẩn bị dữ liệu CRT
    ps = primes
    N = prod(ps)
    weights = []
    for p in ps:
        # Tính trọng số đóng góp của từng p vào tổng N
        M = N // p
        y = inverse_mod(M, p)
        weights.append((M * y) % N)

    # 3. Kỹ thuật Meet-in-the-Middle
    mid = 21
    
    # Tạo bảng Trai (L) - Tất cả các tổ hợp của 21 số đầu với dư 6 hoặc 7
    L = [0]
    for i in range(mid):
        w = weights[i]
        L = [(x + 6*w) % N for x in L] + [(x + 7*w) % N for x in L]
    L.sort() # Sắp xếp để tìm kiếm nhị phân
    
    # Tạo bảng Phải (R)
    R = [0]
    for i in range(mid, 42):
        w = weights[i]
        R = [(x + 6*w) % N for x in R] + [(x + 7*w) % N for x in R]

    # 4. Quét tìm nghiệm
    # Xác định khoảng giá trị mục tiêu (Target Range)
    n_len = (N.bit_length() + 7) // 8
    pad_len = n_len - len(PAYLOAD)
    
    # Giá trị nhỏ nhất (flag# + toàn bit 0)
    t_min = bytes_to_long(PAYLOAD + b'\x00' * pad_len)
    # Giá trị lớn nhất (flag# + toàn bit 1)
    t_max = bytes_to_long(PAYLOAD + b'\xff' * pad_len)

    # Với mỗi phần tử r bên Phải, tìm l bên Trái sao cho l + r rơi vào [t_min, t_max]
    for r_val in R:
        low = (t_min - r_val) % N
        high = (t_max - r_val) % N
        
        # Dùng bisect_left để tìm kiếm cực nhanh trong L
        # ... (Logic tìm kiếm và xử lý wrap-around) ...
        
        # Nếu tìm thấy l, kiểm tra điều kiện xuống dòng
        n = (l_val + r_val) % N
        b = long_to_bytes(n)
        if b.startswith(PAYLOAD) and b'\n' not in b and b'\r' not in b:
            # Gửi n và lấy cờ!
            s.sendall(f"{n}\n".encode())
            print(s.recv(4096))
            return True
    return False
```

> **Flag:** `csd{6767676767676_c85ac0a47cdd255d547197d522770b79}`