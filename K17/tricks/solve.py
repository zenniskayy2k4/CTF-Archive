from pwn import *
from Crypto.Util.number import long_to_bytes
import re
import math

# Kết nối đến server
# r = process(["python3", "chall.py"])
r = remote("challenge.secso.cc", 7005)

# Đọc n và bản mã của cờ
n_line = r.recvline().decode()
c_flag_line = r.recvline().decode()

n = int(re.search(r'n = (\d+)', n_line).group(1))
c_flag = int(c_flag_line)

print(f"n = {n}")
print(f"c_flag = {c_flag}")

n2 = n * n
g = n + 1

# Hàm để tương tác với oracle
def check(trick, x, y):
    r.sendlineafter(b"Which trick do you want to show me? ", trick.encode())
    r.sendlineafter(b"What's the encrypted message you'd like to perform the trick on? ", str(x).encode())
    r.sendlineafter(b"What's the encrypted result of the trick? ", str(y).encode())
    response = r.recvline()
    return b"HOLY SMOKES" in response

# Thiết lập cho binary search
# Cờ dài 32 bytes = 256 bits
FLAG_BITS = 256
low = 0
high = 2**FLAG_BITS - 1

# *** SỬA LỖI: Tăng PADDING để đảm bảo độ dài byte ổn định ***
# PADDING cần lớn hơn nhiều so với 2^256. 2^512 là một lựa chọn an toàn.
PADDING_BITS = 512
PADDING = 1 << PADDING_BITS

# Độ dài byte dự kiến của (m_flag - k + PADDING)
# (m_flag - k + 2**512) sẽ luôn có 513 bit.
# Độ dài byte = ceil(513 / 8) = 65
PADDED_LENGTH = math.ceil( (PADDING_BITS + 1) / 8 ) 

print(f"Using PADDING_BITS = {PADDING_BITS}, stable byte length should be {PADDED_LENGTH}")

# Hệ số nhân tương ứng với độ dài đã được padding
multiplier = 1 + pow(256, PADDED_LENGTH) + pow(256, 2 * PADDED_LENGTH)

# Bắt đầu binary search
while low < high:
    # Sử dụng (low + high + 1) // 2 để tránh vòng lặp vô hạn khi high = low + 1
    mid = (low + high + 1) // 2
    
    # Tạo x mã hóa cho m_flag - mid + PADDING
    modifier = PADDING - mid
    x = (c_flag * pow(g, modifier, n2)) % n2
    
    # Tạo y mã hóa cho (m_flag - mid + PADDING) * multiplier
    y = pow(x, multiplier, n2)

    # Gửi đến oracle
    print(f"Searching... bits left: {math.ceil(math.log2(high-low+1))}", end='\r')
    if check("SAY IT THREE TIMES", x, y):
        # "HOLY SMOKES" => Phỏng đoán đúng => m_flag >= mid
        low = mid
    else:
        # "nup." => Phỏng đoán sai => m_flag < mid
        high = mid - 1

# Kết quả
m_flag = low
print("\n[+] Found flag (int):", m_flag)
try:
    flag = long_to_bytes(m_flag, 32)
    print("[+] Flag:", flag.decode())
except Exception as e:
    print(f"Error converting to bytes: {e}")
    print("Raw bytes:", long_to_bytes(m_flag))


r.close()