from pwn import *

HOST = "9c7f550b17deac08.chal.ctf.ae"
io = remote(host=HOST, port=443, ssl=True, sni=HOST)

io.interactive()