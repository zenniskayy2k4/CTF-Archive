from pwn import *

exe = './average'
elf = ELF(exe)

# Thiết lập terminal để GDB mở cửa sổ mới (quan trọng cho WSL/Linux)
# Nếu bạn dùng tmux thì bỏ comment dòng dưới, không thì cứ để mặc định
context.terminal = ['cmd.exe', '/c', 'start', 'cmd.exe', '/c', 'wsl.exe']

io = process(exe)

def create_player(idx, extra_len, name, msg):
    io.sendlineafter(b'> ', b'1')
    io.sendlineafter(b': ', str(idx).encode())
    io.sendlineafter(b'? ', str(extra_len).encode())
    io.sendlineafter(b': ', name)
    io.sendlineafter(b': ', msg)

print("[-] Đang setup Heap...")

# 1. Tạo 4 chunk rác để đẩy Heap đi xa một chút (ổn định offset)
for i in range(4):
    create_player(i, 0, b'Filler', b'Filler')

# 2. Tạo P4 (Victim) với extra_len = 32 (Con số an toàn mà ta đang nghi ngờ)
# Name: Full 'A' để dễ nhìn
name_pattern = b'A' * 64 
# Message: Full 'B' để phân biệt với Name
msg_pattern = b'B' * 16

print("[-] Tạo Player 4 với Pattern A và B...")
create_player(4, 32, name_pattern, msg_pattern)

# 3. Gắn GDB vào ngay lúc này
# Lệnh GDB tự động chạy khi cửa sổ bật lên
gdb_script = '''
# Dừng chương trình để soi
interrupt

# Tìm xem chuỗi AAAAA... đang nằm đâu
printf "\\n[+] TIM THAY NAME (AAAA...):\\n"
search AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

# Tìm xem chuỗi BBBBB... đang nằm đâu
printf "\\n[+] TIM THAY MESSAGE (BBBB...):\\n"
search BBBBBBBBBBBBBBBB

# Tìm địa chỉ biến Target
printf "\\n[+] DIA CHI TARGET:\\n"
p &target

# In 20 dòng bộ nhớ xung quanh target để nhìn cho rõ
printf "\\n[+] MEMORY DUMP AROUND TARGET:\\n"
x/40gx &target - 0x60
'''

gdb.attach(io, gdbscript=gdb_script)

# Giữ chương trình không thoát
io.interactive()