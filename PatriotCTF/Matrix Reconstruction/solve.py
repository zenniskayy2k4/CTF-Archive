import sys

# --- DỮ LIỆU ĐẦU VÀO ---
states = [
    2694419740, 2430555337, 3055882924, 228605358, 4055459295, 676741477, 1030306057, 1320993926,
    2317712498, 3680836913, 1922319333, 1836782265, 1490734773, 218490631, 4065897775, 3125259028,
    189241330, 1710684784, 2355890305, 95797196, 813001417, 1021781706, 3522243094, 1603928614,
    1122416469, 4125638785, 2423341845, 3666529189, 61609182, 2391267942, 148130332, 4246509548,
    3552866507, 1487751530, 1895017353, 3277260507, 4251037246, 22647618, 3958787364, 227107204
]

# --- CÁC HÀM HỖ TRỢ ---

def get_bit(val, i):
    return (val >> i) & 1

def to_bits(val):
    return [(val >> i) & 1 for i in range(32)]

def from_bits(bits):
    val = 0
    for i, b in enumerate(bits):
        if b: val |= (1 << i)
    return val

def gauss_solve(matrix, target_vector):
    """
    Giải hệ phương trình tuyến tính M * x = v trên GF(2).
    matrix: danh sách các hàng (mỗi hàng là list các bit 0/1).
    target_vector: kết quả mong muốn cho mỗi hàng.
    Trả về: vector nghiệm x (list bit).
    """
    num_equations = len(matrix)
    num_vars = len(matrix[0])
    
    # Tạo ma trận mở rộng [Matrix | Target]
    aug = [row[:] + [target_vector[i]] for i, row in enumerate(matrix)]
    
    pivot_row = 0
    col_to_pivot = {} # Lưu vết cột nào được khử bởi dòng nào
    
    for col in range(num_vars):
        if pivot_row >= num_equations: break
        
        # Tìm dòng có số 1 tại cột hiện tại
        pivot = -1
        for r in range(pivot_row, num_equations):
            if aug[r][col] == 1:
                pivot = r
                break
        
        if pivot != -1:
            # Hoán đổi dòng
            aug[pivot_row], aug[pivot] = aug[pivot], aug[pivot_row]
            col_to_pivot[col] = pivot_row
            
            # Khử các dòng khác
            for r in range(num_equations):
                if r != pivot_row and aug[r][col] == 1:
                    aug[r] = [x ^ y for x, y in zip(aug[r], aug[pivot_row])]
            
            pivot_row += 1
            
    # Truy vết ngược để tìm nghiệm
    solution = [0] * num_vars
    # Với các biến tự do (không có pivot), ta để mặc định là 0
    for col in range(num_vars - 1, -1, -1):
        if col in col_to_pivot:
            r = col_to_pivot[col]
            val = aug[r][-1] # Giá trị đích
            # Trừ đi (XOR) các biến đã giải phía sau
            for c_after in range(col + 1, num_vars):
                if aug[r][c_after] == 1:
                    val ^= solution[c_after]
            solution[col] = val
            
    return solution

def solve_and_decrypt():
    print("[*] Đang xây dựng hệ phương trình để tìm A và B...")
    
    # Chúng ta cần tìm 32 hàng của ma trận A và 32 bit của vector B.
    # Gọi R_i là hàng thứ i của A (vector 32 bit) và b_i là bit thứ i của B.
    # Phương trình: Bit_i(S_{n+1}) = (S_n dot R_i) XOR b_i
    # Ẩn số cho mỗi bit i: 32 bit của R_i + 1 bit b_i = 33 ẩn.
    # Chúng ta có 39 cặp (S_n, S_{n+1}), tức là 39 phương trình cho mỗi bit i.
    
    # Tạo ma trận hệ số (Inputs): [bit0(Sn), bit1(Sn)... bit31(Sn), 1]
    # Số 1 cuối cùng đại diện cho hệ số của b_i
    inputs = []
    for i in range(len(states) - 1):
        row = to_bits(states[i])
        row.append(1) # Hệ số cho B
        inputs.append(row)
        
    A_matrix = [] # Sẽ chứa 32 hàng
    B_vector = [] # Sẽ chứa 32 bit
    
    print("[*] Đang giải Gauss cho từng bit (0..31)...")
    for bit_idx in range(32):
        # Lấy vector kết quả mong muốn (Target): Bit thứ bit_idx của S_{n+1}
        targets = [get_bit(states[i+1], bit_idx) for i in range(len(states) - 1)]
        
        # Giải hệ phương trình
        solution = gauss_solve(inputs, targets)
        
        # Solution có 33 bit: 32 bit đầu là hàng của A, bit cuối là bit của B
        row_A = solution[:32]
        bit_B = solution[32]
        
        A_matrix.append(row_A)
        B_vector.append(bit_B)
        
    print(f"[+] Đã tìm thấy B: {from_bits(B_vector)}")
    
    # --- GIẢI MÃ ---
    try:
        with open("cipher.txt", "rb") as f:
            ciphertext = f.read()
    except FileNotFoundError:
        print("[-] Không tìm thấy cipher.txt. Tạo mẫu test...")
        ciphertext = b"TEST"

    plaintext = bytearray()
    
    # Ta bắt đầu keystream từ state đầu tiên
    current_state_vec = to_bits(states[0])
    
    print("[*] Đang giải mã...")
    for char in ciphertext:
        # Keystream byte là byte thấp nhất
        k = from_bits(current_state_vec) & 0xFF
        plaintext.append(char ^ k)
        
        # Cập nhật state: S_new = A * S_old + B
        new_state_vec = [0] * 32
        for r in range(32):
            # Nhân hàng r của A với state cũ
            dot_prod = 0
            for c in range(32):
                dot_prod ^= A_matrix[r][c] & current_state_vec[c]
            # Cộng bit r của B
            new_state_vec[r] = dot_prod ^ B_vector[r]
            
        current_state_vec = new_state_vec
    
    # Thử in chuỗi
    try:
        print(plaintext.decode('utf-8'))
    except:
        print(plaintext)
        print("\nHex:", plaintext.hex())

if __name__ == "__main__":
    solve_and_decrypt()