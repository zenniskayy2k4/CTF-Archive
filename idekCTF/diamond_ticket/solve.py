# -*- coding: utf-8 -*-

from sage.all import *
import time

# ==============================================================================
# BƯỚC 0: THIẾT LẬP CÁC HẰNG SỐ VÀ GIÁ TRỊ BAN ĐẦU
# ==============================================================================
print("[+] BƯỚC 0: Thiết lập các hằng số")

p = 170829625398370252501980763763988409583
a = 164164878498114882034745803752027154293
b = 125172356708896457197207880391835698381

# Giá trị flag_chocolate đã được xác minh từ việc giải mã RSA ở các bước trước.
# Chúng ta cần nó để kiểm tra lại flag cuối cùng.
flag_chocolate_correct = 99584795316725433978492646071734128819


# ==============================================================================
# BƯỚC 1: GIẢI BÀI TOÁN DLP "HỘP ĐEN"
#
# Lời giải mẫu bắt đầu từ đây. Nó sử dụng một giá trị mục tiêu "am_target"
# đã được tính toán trước. Chúng ta sẽ làm theo logic này.
# ==============================================================================
print("\n[+] BƯỚC 1: Giải Logarit Rời rạc để tìm ràng buộc cho flag")

# Giá trị mục tiêu "am_target" được lấy từ lời giải mẫu.
# Nó là giá trị của a^m_flag (mod p).
am_target = -43867895740074151195419905742714908098

# Thiết lập trường hữu hạn GF(p) để tính toán
F = GF(p)
Fa = F(a)
Fam_target = F(am_target)

# Dùng hàm .log() của Sage để giải DLP: tìm x trong a^x = am_target
# `m_flag_log` là giá trị của flag modulo bậc của a.
m_flag_log = int(Fam_target.log(Fa))
print(f"  - Logarit rời rạc (m_flag_log): {m_flag_log}")

# Bậc (order) của a là chu kỳ lặp của nó. Đây là modulus cho bài toán Dàn.
modulus = int(Fa.multiplicative_order())
print(f"  - Bậc của a (modulus): {modulus}")

# Ràng buộc cốt lõi mà chúng ta tìm được:
# m_flag ≡ m_flag_log (mod modulus)
# Hay: m_flag = m_flag_log + k * modulus


# ==============================================================================
# BƯỚC 2: SỬ DỤNG DÀN (LATTICE) ĐỂ TÌM CÁC BYTE CỦA FLAG
#
# Đây là phần chính của lời giải. Chúng ta biến phương trình trên thành
# một bài toán hình học và dùng thuật toán LLL để tìm ra các byte của flag.
# ==============================================================================
print("\n[+] BƯỚC 2: Sử dụng Dàn (Lattice) để tìm flag")

# --- 2.1: Thiết lập các tham số cho Dàn ---
FLAG_LEN_CONTENT = 20
# `aa` là giá trị "offset" trong kỹ thuật Affine Shift. Lời giải mẫu đã
# thử các giá trị và thấy `aa = 95` (mã ASCII của '_') hoạt động.
aa = 95
print(f"  - Sử dụng Affine Shift với OFFSET (aa) = {aa}")

# --- 2.2: Xây dựng ma trận Dàn ---
# Đây là cách xây dựng ma trận rất cô đọng từ lời giải mẫu.
# Ma trận này được thiết kế để giải bài toán "knapsack" với ràng buộc modular.
# Các hàng của nó sinh ra một không gian vector (dàn) mà trong đó,
# các vector ngắn nhất sẽ tương ứng với lời giải của chúng ta.
print(f"  - Xây dựng ma trận Dàn...")

# Hàng 0..19: identity_matrix(20) -> Mỗi hàng đại diện cho một biến d_i
# Cột 20: vector([0]*20) -> Cột này sẽ liên quan đến hệ số của hằng số
# Cột 21: vector([256**i...]) -> Cột này chứa giá trị `sum(d_i * 256^i)`
M = (identity_matrix(20)
    .augment(vector([0]*20))
    .augment(vector([256**i for i in range(19, -1, -1)]))
)
# Hàng 20: stack(vector([-aa]*20 + [-1, -flag]))
#   - [-aa]*20: Đóng góp `-aa` cho mỗi `d_i`.
#   - [-1]: Hệ số của hằng số.
#   - [-flag]: Đóng góp `-m_flag_log` vào phương trình.
M = M.stack(vector([-aa]*20 + [-1, -m_flag_log]))

# Hàng 21: stack(vector([0]*20 + [0, -modulus]))
#   - Đóng góp `-modulus` vào cột phương trình, liên quan đến biến `k`.
M = M.stack(vector([0]*20 + [0, -modulus]))

# --- 2.3: Gán trọng số và chạy LLL ---
# Gán trọng số lớn cho các cột ràng buộc để LLL ưu tiên tìm lời giải
# làm cho các giá trị ở cột này bằng 0.
M[:,-1] *= 2**16  # Cột cuối cùng (cột phương trình)
M[:,-2] *= 2**8   # Cột áp chót (cột hằng số)
print(f"  - Đã gán trọng số và chuẩn bị chạy LLL...")

print("  - Bắt đầu chạy thuật toán LLL...")
start_time = time.time()
L = M.LLL() # Đây là bước tính toán chính
end_time = time.time()
print(f"  - LLL hoàn thành trong {end_time - start_time:.2f} giây.")

# --- 2.4: Tìm và khôi phục flag từ cơ sở đã rút gọn ---
print("  - Đang tìm kiếm vector lời giải...")
diamond_ticket_found = None
for row in L:
    # Lời giải đúng sẽ thỏa mãn các điều kiện về cấu trúc mà tác giả đã thiết kế
    if row[-1] != 0: # Cột phương trình phải bằng 0
        continue
    
    # Điều kiện về cột hằng số. Nó đảm bảo chúng ta tìm được tổ hợp tuyến tính đúng.
    if row[-2] == 2**8:
        row *= -1
    
    if row[-2] == -2**8:
        try:
            # Khôi phục các ký tự: c_i = d_i + aa
            # `row[:-2]` là 20 giá trị `d_i`
            flag_content_bytes = bytes([i + aa for i in row[:-2]])
            
            # Tạo flag hoàn chỉnh
            diamond_ticket_found = b'idek{' + flag_content_bytes + b'}'
            
            # Thoát ngay khi tìm thấy lời giải đầu tiên hợp lệ
            break
        except (TypeError, ValueError):
            continue

# ==============================================================================
# BƯỚC 3: XÁC MINH VÀ IN KẾT QUẢ
# ==============================================================================
print("\n[+] BƯỚC 3: Xác minh và in kết quả")

def chocolate_generator(m:int) -> int:
    # Cần định nghĩa lại các hằng số bên trong hàm hoặc dùng global
    p_func = 170829625398370252501980763763988409583
    a_func = 164164878498114882034745803752027154293
    b_func = 125172356708896457197207880391835698381
    return (power_mod(a_func, m, p_func) + power_mod(b_func, m, p_func)) % p_func

if diamond_ticket_found:
    # Thực hiện các assert để đảm bảo flag đúng 100%
    assert len(diamond_ticket_found) == 26
    assert diamond_ticket_found.startswith(b"idek{")
    assert diamond_ticket_found.endswith(b"}")
    
    # Chuyển phần nội dung flag sang số nguyên để kiểm tra
    m_final = Integer(diamond_ticket_found[5:-1].hex(), 16)
    
    # Kiểm tra lại với giá trị flag_chocolate ban đầu
    assert chocolate_generator(m_final) == flag_chocolate_correct

    print("\n" + "="*40)
    print("  [!] ĐÃ TÌM THẤY VÀ XÁC MINH FLAG THÀNH CÔNG!")
    print(f"  [!] Flag: {diamond_ticket_found.decode()}")
    print("="*40)
else:
    print("\n[-] Không tìm thấy lời giải. Quá trình đã thất bại.")