from pwn import *
from Crypto.Util.number import long_to_bytes, bytes_to_long

# --- Tiện ích LCG ---
def crack_lcg(outputs):
    """
    Khôi phục a và c từ 3 giá trị output liên tiếp của LCG (x1, x2, x3).
    """
    m = 1 << 64
    x1, x2, x3 = outputs
    
    inv = pow(x2 - x1, -1, m)
    a = ((x3 - x2) * inv) % m
    c = (x2 - a * x1) % m
    return a, c

# --- Kết nối tới server ---
r = remote("e7b613870c70726e.chal.ctf.ae", 443, ssl=True)

# --- Bước 1: Khôi phục LCG và tìm lại seed ban đầu ---
log.info("Bắt đầu khôi phục LCG...")
r.sendlineafter(b"> ", b"2")
# Gửi dòng trống để m=0, từ đó lấy được keystream K
# Keystream này bắt đầu từ trạng thái x_8 của LCG
r.sendlineafter(b"> ", b"") 
lcg_stream_oracle_hex = r.recvline().strip().decode()
lcg_stream_oracle_raw = bytes.fromhex(lcg_stream_oracle_hex)

# Các output này là x_8, x_9, x_10...
oracle_outputs = [bytes_to_long(lcg_stream_oracle_raw[i:i+8]) for i in range(0, 24, 8)]
a, c = crack_lcg(oracle_outputs)
x8_seed = oracle_outputs[0] 

log.success(f"Đã tìm thấy tham số LCG:")
log.success(f"a = {a}")
log.success(f"c = {c}")
log.info(f"Tìm thấy seed của stream thứ hai (x_8) = {x8_seed}")

log.info("Đang đảo ngược LCG để tìm seed ban đầu (x_0)...")
m = 1 << 64
a_inv = pow(a, -1, m)
current_x = x8_seed
# Đảo ngược 8 lần để từ x_8 về x_0
# x_prev = (x_next - c) * a_inv % m
for i in range(8):
    current_x = ((current_x - c) * a_inv) % m

x0_initial_seed = current_x
log.success(f"Đã tìm thấy seed ban đầu (x_0) = {x0_initial_seed}")

# --- Lấy thông tin từ Option 1 ---
log.info("Lấy N và Cflag đã mã hóa...")
r.sendlineafter(b"> ", b"1")
enc_flag_hex = r.recvline().strip().decode()
n = int(r.recvline().strip())
enc_flag = bytes.fromhex(enc_flag_hex)
log.success(f"N = {n}")

# --- Bước 2: Tìm p bằng Binary Search ---
log.info("Bắt đầu tìm p bằng Binary Search...")
low = 1 << 255
high = 1 << 256

for i in range(256 + 5):
    if high == low: break
    mid = (low + high) // 2
    if mid == low: # Tránh vòng lặp vô hạn khi low và high gần nhau
        mid += 1
        
    log.info(f"Vòng lặp {i+1}: Thử mid...")
    
    r.sendlineafter(b"> ", b"2")
    # SỬA LỖI: Chuyển mid thành chuỗi 32-byte để so sánh chính xác
    payload = long_to_bytes(mid, 32)
    r.sendlineafter(b"> ", payload)
    
    response = r.recvline().strip()
    if response == b"too long":
        high = mid
    else:
        low = mid
        
p = high
log.success(f"Đã tìm thấy p = {p}")

# --- Bước 3: Phân tích n và tính khóa bí mật ---
log.info("Phân tích n và tính khóa bí mật...")
if n % p != 0:
    log.error("Binary search thất bại, p không phải là thừa số của n.")
    exit()
q = n // p
log.success(f"Đã tìm thấy q = {q}")

e = 65537
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)
log.success(f"Đã tính được khóa bí mật d")

# --- Bước 4: Lấy Flag ---
log.info("Giải mã flag...")
# Tạo lại LCG với seed ban đầu x_0 để sinh ra keystream chính xác
class TrueLCG:
    def __init__(self, a, c, seed, m=1<<64):
        self.m = m
        self.a = a
        self.c = c
        self.x = seed
    def next(self): 
        self.x=(self.a*self.x+self.c)%self.m
        return self.x
    def stream(self, n):
        out=b""
        while len(out)<n: out+=self.next().to_bytes(8,"big")
        return out[:n]

true_lcg = TrueLCG(a, c, x0_initial_seed)
keystream_for_flag = true_lcg.stream(len(enc_flag))

# Lấy lại Cflag gốc bằng cách XOR với keystream đúng
Cflag_long = bytes_to_long(xor(enc_flag, keystream_for_flag))

# Giải mã
flag_long = pow(Cflag_long, d, n)
flag = long_to_bytes(flag_long)

log.success(f"FLAG: {flag.decode()}")

r.close()