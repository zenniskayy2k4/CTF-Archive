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