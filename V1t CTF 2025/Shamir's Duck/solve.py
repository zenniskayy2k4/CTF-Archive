# Các hàm tính toán nghịch đảo modular (giữ nguyên)
def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    g, y, x = egcd(b % a, a)
    return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    return x % m

def lagrange_interpolate_finite_field(points, p):
    """
    Thực hiện Nội suy Lagrange tại điểm x=0 trên trường hữu hạn GF(p).
    """
    x_coords, y_coords = zip(*points)
    secret = 0
    num_points = len(points)
    
    for i in range(num_points):
        xi, yi = points[i]
        numerator = 1
        denominator = 1
        for j in range(num_points):
            if i != j:
                xj = x_coords[j]
                numerator = (numerator * (p - xj)) % p
                denominator = (denominator * (xi - xj)) % p
        
        lagrange_basis = (numerator * modinv(denominator, p)) % p
        term = (yi * lagrange_basis) % p
        secret = (secret + term) % p
        
    return secret

# --- Dữ liệu đầu vào ---
data = """
Bob-ef73fe834623128e6f43cc923927b33350314b0d08eeb386
Sang-2c17367ded0cd22e15220a2b2a6cede16e2ed64d1898bbad
Khoi-e05fd9646ff27414510dec2e46032469cd60d632606c8181
Long-0c4de736ced3f8412307729b8bea56cc6dc74abce06a0373
Dung-afe15ff509b15eb48b0e9d72fc2285094f6233ec98914312
Steve-cb1a439f208aa76e89236cb496abaf20723191c188e23f54
"""

shares = []
for i, line in enumerate(data.strip().split('\n')):
    name, hex_share = line.split('-')
    x = i + 1
    y = int(hex_share, 16)
    shares.append((x, y))

# --- Tái tạo bí mật ---

# Chọn số nguyên tố p của đường cong SECP256k1 (dài 32 byte)
p = 2**256 - 2**32 - 977

# Lấy 3 shares bất kỳ để tái tạo
shares_to_combine = shares[:3]

secret_as_int = lagrange_interpolate_finite_field(shares_to_combine, p)

# --- Chuyển đổi kết quả và in ra ---

# **SỬA LỖI QUAN TRỌNG TẠI ĐÂY**
# Chuyển toàn bộ số nguyên 256-bit thành chuỗi 32 byte
# (độ dài của p là 256 bit = 32 byte)
secret_bytes_full = secret_as_int.to_bytes(32, 'big')

# Flag của chúng ta là 24 byte cuối cùng của kết quả
secret_bytes_flag = secret_bytes_full[-24:]

# Giải mã chuỗi byte flag thành văn bản
secret_message = secret_bytes_flag.decode('utf-8').strip('\x00')

print(f"Hex của bí mật (24 byte cuối): {secret_bytes_flag.hex()}")
print(f"Flag chính xác: {secret_message}")