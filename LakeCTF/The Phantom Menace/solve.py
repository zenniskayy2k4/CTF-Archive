import json
import numpy as np

# Các tham số từ đề bài
q = 3329
n = 512

# Hàm nhân đa thức trên vành Rq = Zq[x]/(x^n + 1)
# Sao chép từ chall.py để đảm bảo tính toán khớp
def poly_mul(a, b):
    res = np.convolve(a, b)
    # Rút gọn theo modulo x^n = -1
    for i in range(n, len(res)):
        res[i - n] = (res[i - n] - res[i]) % q 
    return res[:n] % q

# Hàm nhân vô hướng hai vector đa thức (dot product)
def vec_poly_mul(v0, v1):
    total = np.zeros(n, dtype=int)
    for a, b in zip(v0, v1):
        total = (total + poly_mul(a, b)) % q
    return total

def solve():
    print("[*] Đang đọc file keys.json...")
    try:
        with open("keys.json", "r") as f:
            data = json.load(f)
    except FileNotFoundError:
        print("Lỗi: Không tìm thấy file keys.json. Hãy tạo file này từ dữ liệu đề bài.")
        return

    # Chuyển đổi dữ liệu sang numpy array
    s = np.array(data["s"]) # Khóa bí mật
    u = np.array(data["u"]) # Một phần bản mã
    v = np.array(data["v"]) # Một phần bản mã

    print("[*] Đang thực hiện giải mã (v - s*u)...")
    
    # Tính s * u (tích vô hướng của 2 vector đa thức)
    s_dot_u = vec_poly_mul(s, u)
    
    # Tính hiệu d = v - s*u (mod q)
    # Đây là giá trị chứa tin nhắn cộng với nhiễu
    m_noisy = (v - s_dot_u) % q
    
    # Khôi phục bit từ m_noisy
    # Bit 1 được map thành khoảng q/2 (~1665)
    # Bit 0 được map thành khoảng 0
    # Ta dùng ngưỡng q/4 và 3q/4 để phân loại
    
    bits = []
    lower_bound = q // 4      # ~ 832
    upper_bound = 3 * q // 4  # ~ 2496
    
    for val in m_noisy:
        if lower_bound < val < upper_bound:
            bits.append(1)
        else:
            bits.append(0)
    
    # Chuyển đổi các bit thành ký tự ASCII
    chars = []
    for i in range(0, len(bits), 8):
        byte_chunk = bits[i:i+8]
        # Nếu không đủ 8 bit (ở cuối) thì bỏ qua hoặc xử lý tùy ý
        if len(byte_chunk) < 8:
            break
        
        # Gom 8 bit thành 1 số nguyên
        char_code = int("".join(map(str, byte_chunk)), 2)
        chars.append(chr(char_code))
        
    flag = "".join(chars)
    print(f"[+] Flag: {flag}")

if __name__ == "__main__":
    solve()