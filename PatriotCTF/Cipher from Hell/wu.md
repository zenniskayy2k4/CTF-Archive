### Phân tích quy trình mã hóa (Encryptor)

1.  **Input**: Flag được chuyển từ chuỗi sang một số nguyên rất lớn `s`.
2.  **Base-3 (Hệ tam phân)**: Code sử dụng `log(s, 3)` và các phép chia/lấy dư cho 3, điều này ám chỉ việc xử lý số `s` dưới dạng hệ cơ số 3.
3.  **Vòng lặp `while c > -1`**:
    *   `s // 3**c`: Lấy chữ số đầu tiên (Most Significant Digit - MSD) trong hệ 3.
    *   `s % 3`: Lấy chữ số cuối cùng (Least Significant Digit - LSD) trong hệ 3.
    *   `o[MSD][LSD]`: Tra bảng `o` (ma trận 3x3) để lấy ra một giá trị (từ 0-8).
    *   `ss *= 9; ss += ...`: Giá trị tra được được đẩy vào biến kết quả `ss` (trong hệ cơ số 9).
    *   **Cập nhật `s`**: `s` bị loại bỏ chữ số đầu và chữ số cuối (lột vỏ hành), `c` giảm đi 2 (vì mất 2 chữ số).

**Tóm lại:** Thuật toán lấy từng cặp "số đầu - số cuối" của `s` (trong hệ 3), tra bảng, rồi ghép vào `ss`. Quy trình đi từ **ngoài vào trong**.

### Chiến thuật giải mã (Decryptor)

Để giải mã, ta làm ngược lại quá trình trên:
1.  Đọc `ss` từ file `encrypted`.
2.  Vì quá trình mã hóa đi từ **ngoài vào trong** và nhân `ss` với 9 sau mỗi bước, chữ số cuối cùng (trong hệ 9) của `ss` sẽ tương ứng với cặp số **trong cùng** của `s`.
3.  Ta sẽ lấy từng chữ số hệ 9 của `ss` (bằng cách `ss % 9`), tra ngược lại bảng `o` để tìm ra cặp `(MSD, LSD)`.
4.  Ghép cặp `(MSD, LSD)` này vào số `s` đang phục hồi. Lưu ý: Lần này ta ghép từ **trong ra ngoài**.

### Script giải (Solver)

Bạn hãy tạo một file tên `solve.py` cùng thư mục với file `encrypted` và chạy đoạn code sau:

```python
import sys

# 1. Định nghĩa ma trận gốc
o = (
    (6, 0, 7),
    (8, 2, 1),
    (5, 4, 3)
)

# 2. Tạo bảng tra ngược (Inverse Lookup)
# Input: Giá trị trong bảng (0-8) -> Output: Tọa độ (row, col) tương ứng
lookup = {}
for r in range(3):
    for c in range(3):
        val = o[r][c]
        lookup[val] = (r, c)

def solve():
    try:
        # 3. Đọc file encrypted
        with open("encrypted", "rb") as f:
            data = f.read()
            # Chuyển bytes thành số nguyên lớn ss
            ss = int.from_bytes(data, byteorder='big')
    except FileNotFoundError:
        print("Lỗi: Không tìm thấy file 'encrypted'. Hãy đảm bảo file này nằm cùng thư mục.")
        return

    s_recovered = 0
    power = 0  # Biến này dùng để theo dõi độ rộng hiện tại của số s (số lượng chữ số hệ 3)

    # 4. Vòng lặp giải mã
    # Chúng ta xử lý từ chữ số cuối cùng của ss (tương ứng với lớp trong cùng của s)
    # đi ngược ra lớp vỏ ngoài cùng.
    while ss > 0:
        # Lấy giá trị được thêm vào sau cùng (hệ 9)
        val = ss % 9
        ss //= 9
        
        # Tìm lại cặp số đầu (row) và cuối (col) tương ứng trong hệ 3
        row, col = lookup[val]
        
        # Công thức tái tạo s từ trong ra ngoài:
        # s_mới = (row * 3^(số_lượng_chữ_số_hiện_tại + 1)) + (s_cũ * 3) + col
        # Giải thích: 
        # - col là chữ số hàng đơn vị (LSD), nên cộng vào cuối.
        # - s_cũ nằm ở giữa, nên nhân 3 (dịch trái 1 đơn vị hệ 3).
        # - row là chữ số hàng lớn nhất (MSD), nên nhân với lũy thừa cao nhất.
        
        if power == 0:
            # Trường hợp khởi tạo (lớp trong cùng)
            s_recovered = row * 3 + col
            power = 2 # Đã có 2 chữ số
        else:
            # Các lớp tiếp theo bao bọc bên ngoài
            # row .... [s_cũ] .... col
            multiplier = 3 ** (power + 1)
            s_recovered = row * multiplier + s_recovered * 3 + col
            power += 2

    # 5. Chuyển số nguyên s đã phục hồi về dạng text (Flag)
    try:
        # Tính số byte cần thiết: (bit_length + 7) // 8
        length = (s_recovered.bit_length() + 7) // 8
        flag = s_recovered.to_bytes(length, byteorder='big')
        print("Flag tìm thấy:")
        print(flag.decode())
    except Exception as e:
        print(f"Đã giải mã ra số, nhưng lỗi khi convert sang text: {e}")
        print(f"Giá trị Hex: {hex(s_recovered)}")

if __name__ == "__main__":
    solve()
```

### Giải thích logic tái tạo (Reconstruction Logic)
Trong code trên, đoạn quan trọng nhất là công thức toán học trong vòng lặp `while`.

Giả sử tại một bước, ta đang có số `s_old` (ví dụ `121` trong hệ 3).
Ta giải mã được lớp vỏ bọc bên ngoài là `(2, 0)` (tức là số đầu là 2, số cuối là 0).
Số mới sẽ có dạng: `2` `[121]` `0` (trong hệ 3).
Để biến đổi về giá trị toán học:
$$s_{new} = 2 \times 3^{\text{độ dài cũ} + 1} + s_{old} \times 3 + 0$$
(Nhân `s_old` với 3 để dịch trái 1 đơn vị chừa chỗ cho số 0, nhân 2 với lũy thừa cao nhất để đặt vào vị trí đầu tiên).