from pwn import *
flag = bytes.fromhex('73626960647f6b206821204f21254f7d694f7624662065622127234f726927756d')
for i in range(256):
    real = xor(flag, i)
    if b'crypto' in real:
        print(real.decode())
        break