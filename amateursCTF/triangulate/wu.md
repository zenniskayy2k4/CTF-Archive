# Write-up: Triangulate (AmateursCTF) - Crypto

## 1. Phân tích đề bài (Source Code Analysis)

Đầu tiên, ta xem xét mã nguồn `chall.py` để hiểu cơ chế hoạt động của bài toán.

### Các tham số:
*   `flag`: Chuỗi bí mật cần tìm.
*   `m`: Một số nguyên tố lớn (`getPrime`), kích thước lớn hơn `flag` một chút. Đây là mô-đun của phép toán.
*   `a`, `c`: Các hệ số ngẫu nhiên, được dùng trong hàm sinh số ngẫu nhiên.

### Hàm sinh số (LCG biến thể):
Bài toán sử dụng **Linear Congruential Generator (LCG)** nhưng có một chút thay đổi (twist) về số lần lặp.

```python
def lcg():
    seed = flag
    # ... khởi tạo a, c ...
    ctr = 0
    while True:
        ctr += 1
        for _ in range(ctr):
            seed = (a * seed + c) % m
        yield seed
```

**Điểm mấu chốt:**
Bình thường LCG sẽ xuất ra trạng thái sau mỗi 1 bước nhảy. Nhưng ở đây, số bước nhảy tăng dần theo biến đếm `ctr`.
*   **Output 1 ($x_1$):** `ctr = 1`. Nhảy 1 bước. Tổng số bước từ đầu: $1$.
*   **Output 2 ($x_2$):** `ctr = 2`. Nhảy thêm 2 bước. Tổng số bước từ đầu: $1 + 2 = 3$.
*   **Output 3 ($x_3$):** `ctr = 3`. Nhảy thêm 3 bước. Tổng số bước từ đầu: $1 + 2 + 3 = 6$.
*   **Output $i$ ($x_i$):** Tổng số bước là dãy số tam giác (Triangular Number): $N_i = \frac{i(i+1)}{2}$.

Chúng ta có 6 output ($x_1, \dots, x_6$) nhưng không biết $m, a, c$ và `flag`.

## 2. Mô hình hóa toán học

### Công thức LCG tổng quát
Công thức cập nhật trạng thái của LCG là:
$$S_{k} = (a \cdot S_{k-1} + c) \pmod m$$

Sau $n$ bước, trạng thái $S_n$ được tính từ trạng thái đầu $S_0$ theo công thức:
$$S_n = a^n S_0 + c \frac{a^n - 1}{a - 1} \pmod m$$

Công thức này khá cồng kềnh vì chứa phép cộng. Để đơn giản hóa, ta sử dụng kỹ thuật **Affine Shift** (Dịch chuyển affine) để đưa về dạng cấp số nhân thuần túy.

### Kỹ thuật Affine Shift
Ta tìm một số $u$ sao cho dãy số $y_n = S_n + u$ tuân theo quy luật $y_n = a^k \cdot y_0$.
Đặt $S_{next} + u = a(S_{curr} + u)$.
Triển khai ra:
$$S_{next} = a \cdot S_{curr} + a \cdot u - u$$
So sánh với phương trình gốc $S_{next} = a \cdot S_{curr} + c$, ta có:
$$c = u(a - 1) \implies u = c(a - 1)^{-1} \pmod m$$

Khi đó, trạng thái tại bước thứ $k$ có thể viết gọn là:
$$x + u = a^k (S_0 + u) \pmod m$$

### Áp dụng vào bài toán
Gọi $x_1, x_2, x_3, \dots$ là các giá trị nhận được (outputs).
Gọi $k_i$ là tổng số bước nhảy tương ứng. Ta có:
1.  $x_1 + u = a^1 (S_0 + u)$
2.  $x_2 + u = a^3 (S_0 + u)$
3.  $x_3 + u = a^6 (S_0 + u)$
4.  $x_4 + u = a^{10} (S_0 + u)$

## 3. Xây dựng phương trình loại bỏ ẩn số

Hiện tại ta có quá nhiều ẩn ($a, S_0, m, u$). Ta sẽ tìm cách loại bỏ $S_0$ và $a$ để tìm $u$ và $m$.

### Bước 1: Loại bỏ cụm $(S_0 + u)$
Ta xét tỷ lệ giữa các output liên tiếp (đã cộng $u$):

$$\frac{x_2 + u}{x_1 + u} = \frac{a^3(S_0+u)}{a^1(S_0+u)} = a^2$$
$$\frac{x_3 + u}{x_2 + u} = \frac{a^6(S_0+u)}{a^3(S_0+u)} = a^3$$
$$\frac{x_4 + u}{x_3 + u} = \frac{a^{10}(S_0+u)}{a^6(S_0+u)} = a^4$$

### Bước 2: Loại bỏ $a$
Ta có mối quan hệ giữa các lũy thừa của $a$:
$$(a^2)^3 = (a^3)^2$$
Thay thế các tỷ lệ vào:
$$\left( \frac{x_2 + u}{x_1 + u} \right)^3 \equiv \left( \frac{x_3 + u}{x_2 + u} \right)^2 \pmod m$$

Nhân chéo để khử mẫu số:
$$(x_2 + u)^3 (x_2 + u)^2 - (x_3 + u)^2 (x_1 + u)^3 \equiv 0 \pmod m$$
$$(x_2 + u)^5 - (x_1 + u)^3 (x_3 + u)^2 \equiv 0 \pmod m$$

Đặt đa thức này là $P_2(u)$. Đây là một đa thức biến $u$, bậc 5.

Tương tự, ta thiết lập quan hệ giữa $a^3$ và $a^4$ (từ bộ $x_2, x_3, x_4$):
$$(a^3)^4 = (a^4)^3 \implies \left( \frac{x_3 + u}{x_2 + u} \right)^4 \equiv \left( \frac{x_4 + u}{x_3 + u} \right)^3 \pmod m$$
$$(x_3 + u)^7 - (x_4 + u)^3 (x_2 + u)^4 \equiv 0 \pmod m$$

Đặt đa thức này là $P_3(u)$.

## 4. Khôi phục mô-đun $m$ và $u$

### Tìm $m$ (Modulus Recovery)
Ta có hai đa thức $P_2(u)$ và $P_3(u)$. Chúng có cùng một nghiệm $u$ thực sự trong trường $\mathbb{Z}_m$.
Theo tính chất đại số:
> Nếu hai đa thức có nghiệm chung, thì **Hợp thức (Resultant)** của chúng phải bằng 0 (hoặc trong trường hợp này là chia hết cho $m$).

Ta tính:
*   $R_{23} = \text{Resultant}(P_2(u), P_3(u))$
*   $R_{34} = \text{Resultant}(P_3(u), P_4(u))$ (Dùng thêm bộ $x_3, x_4, x_5$ để chắc chắn).

Số $m$ phải là ước chung của các Resultant này.
$$m = \text{GCD}(R_{23}, R_{34})$$

*Lưu ý thực tế:* GCD tìm được thường là một số rất lớn và có thể là bội số của số nguyên tố $m$ cần tìm (ví dụ: $k \cdot m \cdot 2^{100} \dots$). Ta cần chia cho các thừa số nhỏ (2, 3, 5...) để lọc ra số nguyên tố $m$.

### Tìm $u$
Sau khi đã biết $m$, ta quay lại giải hệ phương trình đa thức trên vành $\mathbb{Z}_m$.
Nghiệm $u$ chính là nghiệm chung của $P_2(u)$ và $P_3(u) \pmod m$.
Ta tìm ước chung lớn nhất của hai đa thức (Polynomial GCD):
$$G(u) = \text{GCD}(P_2(u), P_3(u)) \pmod m$$

Kết quả $G(u)$ thường sẽ là một nhị thức bậc nhất dạng $A \cdot u + B$.
Nghiệm là:
$$u \equiv -B \cdot A^{-1} \pmod m$$

## 5. Khôi phục Flag

Sau khi có $m$ và $u$, mọi thứ trở nên đơn giản:

1.  **Tính $a$:**
    Ta đã biết $a^2 = \frac{x_2+u}{x_1+u}$ và $a^3 = \frac{x_3+u}{x_2+u}$.
    $$a = a^3 \cdot (a^2)^{-1} \pmod m$$

2.  **Tính $c$:**
    Từ công thức chuyển đổi $u = c(a-1)^{-1}$, ta suy ra:
    $$c = u(a - 1) \pmod m$$

3.  **Tính $S_0$ (Flag):**
    Ta có $x_1$ là trạng thái sau 1 bước nhảy từ $S_0$:
    $$x_1 = a \cdot S_0 + c \pmod m$$
    Suy ra:
    $$S_0 = (x_1 - c) \cdot a^{-1} \pmod m$$

4.  **Decode:** Chuyển số nguyên $S_0$ thành bytes để lấy flag.

## 6. Tổng kết code (Logic luồng đi)

1.  **Input:** Lấy 6 số output từ đề bài.
2.  **SymPy Poly:** Tạo các đa thức $P_i(u)$ bằng thư viện SymPy.
3.  **Resultant:** Tính Resultant của các cặp đa thức để loại bỏ $u$.
4.  **GCD Integer:** Tính GCD của các Resultant để tìm bội của $m$. Lọc các thừa số nhỏ để lấy $m$ nguyên tố.
5.  **Poly GCD Mod $m$:** Tính GCD của các đa thức trên trường $\mathbb{Z}_m$ để tìm phương trình bậc nhất chứa $u$. Giải tìm $u$.
6.  **Backtrack:** Tính ngược lại $a \to c \to \text{flag}$.

## 7. Bài học rút ra (Key Takeaways)
*   **LCG không an toàn:** Ngay cả khi ẩn số lần lặp hay mô-đun, LCG vẫn dễ bị tấn công nếu lộ ra một vài output liên tiếp do tính chất tuyến tính của nó.
*   **Affine Shift:** Kỹ thuật thêm hằng số $u$ để biến đổi $ax+c$ thành phép nhân $a(x+u)$ là cực kỳ hữu ích trong việc giải các bài toán LCG ẩn tham số.
*   **Resultant:** Là công cụ mạnh mẽ trong mật mã học (đặc biệt là tấn công RSA kiểu Franklin-Reiter) để loại bỏ biến chung giữa hai phương trình đa thức mà không cần giải trực tiếp.