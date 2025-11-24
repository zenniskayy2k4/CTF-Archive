from pwn import *
print(f"crypto{{{xor(b'label', 13).decode()}}}")

print(f"crypto{{{bytes([b ^ 13 for b in b'label']).decode()}}}")