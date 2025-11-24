from pwn import *
exe = ELF('./chal')
rop = ROP(exe)
print("Gadgets found:")
print(rop.gadgets)

print("\nSearching for pop rdi:")
try:
    print(rop.find_gadget(['pop rdi', 'ret']))
except:
    print("No 'pop rdi' found!")

print("\nSearching for pop rsi:")
try:
    print(rop.find_gadget(['pop rsi', 'ret'])) # Hoặc pop rsi; pop r15; ret
except:
    print("No 'pop rsi' found!")