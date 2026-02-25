import socket
import re
import sys
import random
import time
from Crypto.Util.number import bytes_to_long, long_to_bytes, inverse
import ssl

# --- Cấu hình ---
HOST = 'candles.ctf.prgy.in'
PORT = 1337
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF61  # 2^128 - 159
SUFFIX_LEN = 48
A_PREFIX = b"I approve the agreement:\n"    # 25 bytes
B_PREFIX = b"I authorize the transaction:\n" # 29 bytes

def padding(x):
    return x + bytes([len(x) & 255])

def get_printable_high():
    # Tạo chuỗi 32 bytes ngẫu nhiên in được
    # Tránh ký tự đặc biệt có thể gây lỗi khi gửi qua socket (dù server lọc range 32-126)
    chars = list(range(48, 123)) # 0-9, A-Z, a-z
    return bytes([random.choice(chars) for _ in range(32)])

def is_printable(n, length=16):
    # Kiểm tra nhanh số nguyên n có tạo thành chuỗi in được không
    # Tối ưu hóa: Check từng byte từ thấp lên cao
    if n < 0: return False
    for _ in range(length):
        byte = n & 0xFF
        if byte < 32 or byte > 126: return False
        n >>= 8
    return n == 0 # Phải hết đúng sau length bytes

def solve():
    print(f"[*] Đang kết nối tới {HOST}:{PORT}...")
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s = context.wrap_socket(sock, server_hostname=HOST)
    s.connect((HOST, PORT))

    def read_until(txt):
        buf = b""
        while txt.encode() not in buf:
            try:
                data = s.recv(1)
                if not data: break
                buf += data
            except: break
        return buf

    # --- BƯỚC 1: LẤY SIGNATURE ---
    read_until("> ")
    s.sendall(b"1\n")
    read_until("Suffix:")
    suffix1 = b"A" * SUFFIX_LEN
    s.sendall(suffix1 + b"\n")
    
    response = read_until("X =").decode()
    sig_match = re.search(r"SIG: (0x[0-9a-f]+)", response)
    if not sig_match:
        print("[-] Lỗi: Không lấy được Signature.")
        return
    sig = sig_match.group(1)
    print(f"[+] Got Signature.")

    # --- BƯỚC 2: TÍNH TOÁN CONSTANT ---
    m1 = padding(A_PREFIX + suffix1)
    x1 = bytes_to_long(m1)
    target_mod = x1 % P
    
    # Phương trình: Low = (Target - PrefixB_term - Len - High * 159 * 256) / 256  (mod P)
    # Rút gọn: Low = C_CONST - High * 159 (mod P)
    
    term_b = (bytes_to_long(B_PREFIX) << 392) % P
    term_len = 77
    
    # C_CONST = (Target - term_b - term_len) * inv(256)
    inv_256 = inverse(256, P)
    c_const = ((target_mod - term_b - term_len) * inv_256) % P
    
    print(f"[*] Bắt đầu tìm kiếm Hybrid (Target: {target_mod})...")
    
    start_time = time.time()
    attempts = 0
    found_suffix = None
    
    # --- BƯỚC 3: VÒNG LẶP HYBRID ---
    # Chiến thuật: Random High -> Check 12 bytes đầu -> Nếu OK thì Brute-force 4 bytes cuối
    
    while not found_suffix:
        attempts += 1
        if attempts % 10000 == 0:
            sys.stdout.write(f"\r[*] Đang thử: {attempts} High randoms... ({time.time()-start_time:.1f}s)")
            sys.stdout.flush()
            
        # 1. Random High
        high_bytes = get_printable_high()
        high_val = bytes_to_long(high_bytes)
        
        # 2. Tính Low Base
        # Low = (C - High * 159) % P
        # Tính toán trên số lớn hơi chậm, nhưng cần thiết để nhảy cóc
        current_low = (c_const - high_val * 159) % P
        
        # 3. Quick Check: Top 12 bytes (MSB) của Low
        # Low phải đủ 16 bytes. 
        # Lấy 12 bytes cao: shift phải 32 bit (4 bytes cuối)
        top_part = current_low >> 32
        
        # Kiểm tra nhanh top 12 bytes có in được không
        if not is_printable(top_part, length=12):
            continue
            
        # 4. Fine-tuning: Top 12 bytes đã đẹp! Giờ sửa 4 bytes cuối (LSB)
        # Ta tăng High lên k đơn vị -> Low giảm k*159 đơn vị
        # Mục tiêu: Sửa 4 bytes cuối mà không làm hỏng 12 bytes đầu
        # Giới hạn thử: 5000 bước (đủ để quét xác suất 1/50 của các bytes cuối)
        
        temp_low = current_low
        temp_high = high_val
        
        for k in range(5000):
            # Check full 16 bytes
            if is_printable(temp_low, length=16):
                # SUCCESS!
                final_high_bytes = long_to_bytes(temp_high)
                final_low_bytes = long_to_bytes(temp_low)
                
                # Double check độ dài (đề phòng mất số 0 đầu)
                if len(final_low_bytes) < 16:
                    # Pad thêm byte in được nếu thiếu (hiếm)
                    # Thực ra nếu thiếu tức là byte đầu là 0 -> fail is_printable rồi
                    pass 
                else:
                    found_suffix = final_high_bytes + final_low_bytes
                    print(f"\n\n[+] TÌM THẤY SUFFIX SAU {attempts} attempts!")
                    print(f"    Suffix: {found_suffix}")
                    break
            
            # Cập nhật cho vòng sau: High + 1 => Low - 159
            temp_low = temp_low - 159
            if temp_low < 0: temp_low += P
            temp_high += 1
        
        if found_suffix: break

    # --- BƯỚC 4: GỬI KẾT QUẢ VÀ NHẬN FLAG ---
    print("[*] Đang gửi payload...")
    
    # Đọc hết các dữ liệu thừa còn sót lại trong buffer trước khi gửi lệnh mới
    s.settimeout(0.5)
    try:
        while s.recv(1024): pass
    except:
        pass
    s.settimeout(None) # Bỏ timeout để chờ server xử lý

    # Gửi lựa chọn 2
    s.sendall(b"2\n")
    
    # Đợi server hỏi "Suffix:"
    # Dùng vòng lặp đọc để chắc chắn nhận được đúng prompt
    buff = b""
    while b"Suffix:" not in buff:
        buff += s.recv(1)
    
    # Gửi Suffix đã tìm được
    s.sendall(found_suffix + b"\n")
    
    # Đợi server hỏi "Signature:"
    buff = b""
    while b"Signature:" not in buff:
        buff += s.recv(1)

    # Gửi Signature cũ
    s.sendall(sig.encode() + b"\n")
    
    print("[*] Đã gửi xong. Đang đợi Flag...")

    # Đọc liên tục cho đến khi server đóng kết nối
    final_response = b""
    while True:
        try:
            chunk = s.recv(4096)
            if not chunk: break # Server đóng kết nối -> Dừng
            final_response += chunk
            print(chunk.decode(errors='ignore'), end="") # In ngay khi nhận được
        except Exception:
            break
            
    print("\n" + "="*40)
    # Double check: In lại toàn bộ
    print("Full Response:", final_response.decode(errors='ignore'))
    print("="*40)

if __name__ == "__main__":
    solve()