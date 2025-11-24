from pwn import *

HOST = "146bb2b46937b94a.chal.ctf.ae"
io = remote(host=HOST, port=443, ssl=True, sni=HOST)

io.interactive()