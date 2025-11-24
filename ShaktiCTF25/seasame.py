import ctypes

# -----------------------------------------------------------------------------
# Helper Functions - Tái tạo các hàm của C trong Python
# -----------------------------------------------------------------------------

# Để đảm bảo kết quả rand() giống hệt trong C, chúng ta dùng ctypes
# để gọi trực tiếp hàm srand và rand từ thư viện chuẩn của C (libc)
libc = ctypes.CDLL("libc.so.6")

def srand(seed):
    """Gọi hàm srand của C."""
    libc.srand(seed)

def rand():
    """Gọi hàm rand của C."""
    return libc.rand()

# Hàm xoay phải (right rotate) 32-bit
def r_rotate(val, n):
    """Xoay phải giá trị 32-bit `val` đi `n` bits."""
    n = n % 32
    return ((val >> n) | (val << (32 - n))) & 0xFFFFFFFF

# Hàm xoay trái (left rotate) 32-bit
def l_rotate(val, n):
    """Xoay trái giá trị 32-bit `val` đi `n` bits."""
    n = n % 32
    return ((val << n) | (val >> (32 - n))) & 0xFFFFFFFF

# -----------------------------------------------------------------------------
# Dữ liệu từ chương trình
# -----------------------------------------------------------------------------

# Mảng hằng số `local_118` mà chương trình dùng để so sánh
final_values = [
    0x159, 0x138, 0x123, 0x141, 0x15c, 0x13b, 0x129, 0x15c,
    0x132, 0x171, 0xd8, 0x13b, 0x13b, 0x93, 0x13b, 0x93,
    0x13b, 0x93, 0x13b, 0x13b, 0x11d, 0x11a, 0x11d, 0x11a,
    0x11d, 0x11d, 0x99, 0x96, 0x9c, 0x99, 0x96, 0x9c,
    0x96, 0x11d, 0x99, 0x14a, 0x13e, 0x90, 0x16b, 0x11d,
    0x156, 0x99, 0x162, 0x11d, 0x11a, 0x11d, 0x177
]

# -----------------------------------------------------------------------------
# Quá trình đảo ngược
# -----------------------------------------------------------------------------

# Bắt đầu với các giá trị cuối cùng, chúng ta sẽ gọi nó là `current_values`
current_values = list(final_values)
password_len = len(current_values)

# Bước 1: Đảo ngược Biến đổi #6 (r_rotate(x, 35) * 3)
# -> Chia cho 3, sau đó xoay trái 35 bits
for i in range(password_len):
    # Chia cho 3
    val = current_values[i] // 3
    # Xoay trái 35 bits
    current_values[i] = l_rotate(val, 35)

# Bước 2: Đảo ngược Biến đổi #5 (l_rotate(x, 3))
# -> Xoay phải 3 bits
for i in range(password_len):
    current_values[i] = r_rotate(current_values[i], 3)

# Bước 3: Đảo ngược Biến đổi #4 (XOR với seed_two)
srand(0x59334)
for i in range(password_len):
    current_values[i] ^= rand()

# Bước 4: Đảo ngược Biến đổi #3 (XOR với seed_one)
srand(0x4f347)
for i in range(password_len):
    current_values[i] ^= rand()

# Bước 5: Đảo ngược Biến đổi #2 (XOR với seed_two)
srand(0x59334)
for i in range(password_len):
    current_values[i] ^= rand()

# Bước 6: Đảo ngược Biến đổi #1 (XOR với seed_one)
srand(0x4f347)
for i in range(password_len):
    current_values[i] ^= rand()

# -----------------------------------------------------------------------------
# Kết quả
# -----------------------------------------------------------------------------

# `current_values` bây giờ chứa các giá trị ASCII của mật khẩu
# Chuyển đổi các giá trị số thành ký tự
flag = ""
for val in current_values:
    flag += chr(val)

print("The magic password is:")
print(flag)