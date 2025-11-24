import re

# Hàm giả lập kiểu long 64-bit của Java (quan trọng nhất!)
# Giúp Python hiểu được cơ chế tràn số (overflow) giống Java
def u64(n):
    n = n % (2**64)
    if n >= 2**63:
        n -= 2**64
    return n

def check_polynomial(x, block):
    s = 0
    degree = len(block)
    
    # Tính giá trị đa thức: C_0*x^n + C_1*x^(n-1) + ...
    # Phải áp dụng u64() sau MỖI phép tính cộng hoặc nhân
    for i, coeff in enumerate(block):
        power = degree - i 
        # Tính x^power
        term_val = coeff * (x ** power)
        # Apply overflow cho phép nhân
        term_val = u64(term_val)
        
        # Cộng vào tổng và apply overflow ngay lập tức
        s = u64(s + term_val)
        
    return s == 0

def main():
    try:
        with open('Main.j', 'r') as f:
            lines = f.readlines()
    except FileNotFoundError:
        print("Lỗi: Không tìm thấy file 'Main.j'.")
        return

    all_blocks = []
    current_block_coeffs = []

    # Regex tìm số Long (ldc2_w)
    regex_long = re.compile(r'ldc2_w\s+(-?\d+)L')
    
    for line in lines:
        # 1. Tìm hệ số trong dòng
        match = regex_long.search(line)
        if match:
            val = int(match.group(1))
            current_block_coeffs.append(val)
        
        # 2. Gặp lệnh nhảy ifgt -> Kết thúc 1 block phương trình
        if 'ifgt' in line:
            if current_block_coeffs:
                all_blocks.append(current_block_coeffs)
                current_block_coeffs = []

    # Xử lý block cuối nếu còn sót
    if current_block_coeffs:
        all_blocks.append(current_block_coeffs)

    flag = ""
    
    # Đảo ngược danh sách để giải từ ký tự đầu tiên (Bottom-up)
    for i, coeffs in enumerate(reversed(all_blocks)):
        found = False
        # Thử các ký tự in được trong bảng mã ASCII
        for char_code in range(32, 127):
            if check_polynomial(char_code, coeffs):
                flag += chr(char_code)
                found = True
                break
        
        if not found:
            # Fallback: Đôi khi logic phương trình lệch bậc x một chút, 
            # thử lại với logic bậc giảm đi 1 (power = degree - i - 1)
            # Nhưng thường code trên đã chuẩn với logic bài này.
            flag += "?"
            print(f"Block {i+1}: Không tìm thấy nghiệm!")

    print(f"FLAG: {flag}")

if __name__ == "__main__":
    main()