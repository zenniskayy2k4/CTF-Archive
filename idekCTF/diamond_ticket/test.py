import string
from itertools import product
import time

# --- Dữ liệu từ các bước trước ---
p = 170829625398370252501980763763988409583
a = 164164878498114882034745803752027154293
# X1 là mục tiêu a^m_flag = X1 (mod p)
X1 = 3326911817425229537915516566381042782

def bytes_to_long(b):
    return int.from_bytes(b, 'big')

print("[+] Bắt đầu tấn công Meet-in-the-Middle trên máy cục bộ...")

# Giả định flag có 8 ký tự, chia thành 4+4
k_total = 8
k_split = k_total // 2

# Bộ ký tự có thể có trong flag (an toàn)
# charset = string.ascii_letters + string.digits + "_-{}!?"
# Bộ ký tự hẹp hơn để thử nếu muốn nhanh hơn
charset = string.ascii_lowercase + string.digits + "_"

# --- Baby Steps ---
baby_steps_map = {}
num_baby_steps = len(charset)**k_split
print(f"  [-] Giai đoạn 1: Tạo bảng Baby Steps với {num_baby_steps} giá trị...")
start_time = time.time()

for i, s_low_tuple in enumerate(product(charset, repeat=k_split)):
    if (i + 1) % 1000000 == 0:
        elapsed = time.time() - start_time
        print(f"      ... đã xử lý {i+1}/{num_baby_steps} ({((i+1)/num_baby_steps)*100:.1f}%) trong {elapsed:.2f} giây")
        
    s_low = "".join(s_low_tuple)
    m_low = bytes_to_long(s_low.encode('utf-8'))
    val = pow(a, m_low, p)
    baby_steps_map[val] = s_low

end_time = time.time()
print(f"  [-] Bảng Baby Steps đã được tạo xong trong {end_time - start_time:.2f} giây.")

# --- Giant Steps ---
# Ta cần tính g_inv = (a^(256^k_split))^-1 mod p
# a^(-m_high * 256^k_split) = (a^(-256^k_split))^m_high
# Chú ý: tính lũy thừa của số mũ trong phép tính mod p-1
# g_inv = pow(a, -pow(256, k_split, p-1), p)
# Tuy nhiên, cách này có thể sai nếu p-1 không phải là bậc của a.
# Cách an toàn hơn:
g = pow(a, pow(256, k_split), p)
g_inv = pow(g, -1, p)

num_giant_steps = len(charset)**k_split
print(f"  [-] Giai đoạn 2: Thực hiện Giant Steps với {num_giant_steps} giá trị...")
start_time = time.time()

found = False
for i, s_high_tuple in enumerate(product(charset, repeat=k_split)):
    if (i + 1) % 1000000 == 0:
        elapsed = time.time() - start_time
        print(f"      ... đã xử lý {i+1}/{num_giant_steps} ({((i+1)/num_giant_steps)*100:.1f}%) trong {elapsed:.2f} giây")

    s_high = "".join(s_high_tuple)
    m_high = bytes_to_long(s_high.encode('utf-8'))
    
    # target = X1 * (a^m_high_full)^-1 = X1 * (g^m_high)^-1 = X1 * g_inv^m_high
    target = (X1 * pow(g_inv, m_high, p)) % p
    
    if target in baby_steps_map:
        s_low = baby_steps_map[target]
        flag_content = s_high + s_low
        print("\n" + "="*40)
        print(f"  [!] ĐÃ TÌM THẤY FLAG!")
        print(f"  [!] idek{{{flag_content}}}")
        print("="*40)
        found = True
        break

end_time = time.time()
print(f"  [-] Giai đoạn Giant Steps kết thúc trong {end_time - start_time:.2f} giây.")

if not found:
    print("\n[-] Không tìm thấy flag. Hãy thử với bộ ký tự hoặc độ dài khác.")