import json

# Tham số
q = 251
n = 16
k = 2

# 1. Load dữ liệu
try:
    with open('keys.json', 'r') as f:
        data = json.load(f)
except FileNotFoundError:
    print("Không tìm thấy file keys.json. Hãy tạo file này từ dữ liệu đề bài.")
    exit()

A_list = data['A']
t_list = data['t']
u_list = data['u']
v_list = data['v']

# 2. Xây dựng ma trận cho Lưới (Lattice Construction)

# Hàm tạo ma trận Negacyclic cho một đa thức
# Phép nhân đa thức a(x)*b(x) mod (x^n + 1) tương đương Matrix(a) * vector(b)
def negacyclic_matrix(poly_coeffs):
    mat = []
    for i in range(n):
        row = []
        for j in range(n):
            # Hệ số của x^i trong a(x) * x^j
            # Nếu j <= i: là coeff tại (i-j)
            # Nếu j > i: là -coeff tại (n + i - j) do x^n = -1
            if j <= i:
                val = poly_coeffs[i-j]
            else:
                val = -poly_coeffs[n + i - j]
            row.append(val)
        mat.append(row)
    return matrix(ZZ, mat)

# Xây dựng ma trận lớn A_mat (k*n x k*n) từ ma trận đa thức A
# A là k x k đa thức. Mỗi đa thức chuyển thành block n x n.
blocks = [[None for _ in range(k)] for _ in range(k)]
for r in range(k):
    for c in range(k):
        blocks[r][c] = negacyclic_matrix(A_list[r][c])
        
A_mat = block_matrix(blocks)

# Xây dựng vector t (k*n)
t_vec = []
for poly in t_list:
    t_vec.extend(poly)
t_vec = vector(ZZ, t_vec)

# Xây dựng lưới để tấn công tìm s
# Ta có A_mat * s = t_vec - e (mod q)
# Xây dựng lưới với basis:
# [ I (dim)     A_mat.T (dim)    0 ]
# [ 0           q*I (dim)        0 ]
# [ 0           -t_vec           1 ]
# Một vector ngắn trong lưới này sẽ có dạng (s, -e, 1)

dim = k * n # 32
L_basis = matrix(ZZ, 2*dim + 1, 2*dim + 1)

# Block Identity cho s
L_basis.set_block(0, 0, matrix.identity(dim))
# Block A_mat.T (map s sang A*s)
L_basis.set_block(0, dim, A_mat.transpose())
# Block q*I (để modulo q)
L_basis.set_block(dim, dim, q * matrix.identity(dim))
# Vector -t
L_basis.set_block(2*dim, dim, matrix(ZZ, 1, dim, [-x for x in t_vec]))
# Số 1 ở cuối
L_basis[2*dim, 2*dim] = 1

print("[-] Đang chạy LLL để tìm khóa bí mật s...")
L_reduced = L_basis.LLL()

# Tìm vector chứa s
s_found = None
for row in L_reduced:
    # Kiểm tra phần tử cuối cùng là 1 hoặc -1
    if row[-1] == 1:
        s_cand = row[:dim]
    elif row[-1] == -1:
        s_cand = -row[:dim]
    else:
        continue
    
    # Kiểm tra heuristic: các hệ số của s phải nhỏ (thường là -1, 0, 1)
    if all(abs(x) <= 2 for x in s_cand):
        s_found = s_cand
        break

if s_found is None:
    print("[!] Không tìm thấy s. Thử kiểm tra lại tham số.")
    exit()

print("[+] Đã tìm thấy s!")

# Chuyển s về dạng list of lists (k polynomials)
s_polys = []
for i in range(k):
    s_polys.append(list(s_found[i*n : (i+1)*n]))

# 3. Giải mã (Decryption)
# Hàm nhân vector đa thức
def vec_poly_mul_dot(s_vec, u_vec):
    # s_vec: list of k polys
    # u_vec: list of k polys
    # result: single poly
    final_poly = [0] * n
    
    for i in range(k):
        # Nhân poly s[i] với u[i]
        # Dùng hàm convolve đơn giản của python + modulo
        # (Hoặc dùng lại logic matrix ở trên nhưng chậm hơn, viết trực tiếp cho nhanh)
        p1 = s_vec[i]
        p2 = u_vec[i]
        
        # Convolve
        res = [0] * (2*n - 1)
        for x in range(len(p1)):
            for y in range(len(p2)):
                res[x+y] += p1[x] * p2[y]
        
        # Modulo x^n + 1
        poly_res = [0] * n
        for j in range(len(res)):
            if j < n:
                poly_res[j] += res[j]
            else:
                poly_res[j-n] -= res[j] # x^n = -1
        
        # Cộng dồn vào kết quả tổng
        for j in range(n):
            final_poly[j] = (final_poly[j] + poly_res[j])
            
    return [x % q for x in final_poly]

flag_bits = []

print("[-] Đang giải mã các bản tin...")
# u_list shape: (batch, k, n)
# v_list shape: (batch, n)
for idx in range(len(u_list)):
    u_batch = u_list[idx]
    v_batch = v_list[idx]
    
    # Tính s * u
    su = vec_poly_mul_dot(s_polys, u_batch)
    
    # Tính m ~ v - s*u
    diff = [(v_batch[i] - su[i]) % q for i in range(n)]
    
    # Decode bits
    # 0 maps to 0, 1 maps to q/2 ~ 125
    # Ngưỡng (Threshold): q/4 ~ 62 và 3q/4 ~ 188
    # Nếu trong khoảng [62, 188] -> 1, còn lại -> 0
    chunk_bits = []
    for val in diff:
        if 62 < val < 188:
            chunk_bits.append(1)
        else:
            chunk_bits.append(0)
    flag_bits.extend(chunk_bits)

# 4. Chuyển bits thành ký tự
chars = []
# Gom nhóm 8 bits
for i in range(0, len(flag_bits), 8):
    byte_vals = flag_bits[i:i+8]
    if len(byte_vals) < 8: break # Bỏ qua phần thừa nếu có
    char_code = int("".join(str(b) for b in byte_vals), 2)
    chars.append(chr(char_code))

print("Flag:", "".join(chars))