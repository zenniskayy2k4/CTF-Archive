from pwn import *
import re

# Cấu hình kết nối
HOST = 'auratester.ctf.pascalctf.it'
PORT = 7001

def solve():
    # Kết nối đến server
    print(f"[*] Connecting to {HOST}:{PORT}...")
    r = remote(HOST, PORT)

    # Nhập tên
    r.sendlineafter(b"> ", b"Hacker")

    # --- PHẦN 1: KIẾM AURA ---
    # Chọn menu 1: Trả lời câu hỏi
    r.sendlineafter(b"> ", b"1")

    # Trả lời 4 câu hỏi để đạt 700 điểm (YES, NO, YES, NO)
    # Câu 1: Do you believe in the power of aura? -> yes (+150)
    r.recvuntil(b"(yes/no)")
    r.sendline(b"yes")
    
    # Câu 2: Do you a JerkMate account? -> no (+50)
    r.recvuntil(b"(yes/no)")
    r.sendline(b"no")
    
    # Câu 3: Are you willing to embrace your inner alpha? -> yes (+450)
    r.recvuntil(b"(yes/no)")
    r.sendline(b"yes")
    
    # Câu 4: Do you really like SHYNE...? -> no (+50)
    r.recvuntil(b"(yes/no)")
    r.sendline(b"no")

    print("[+] Questions answered. Aura should be 700.")

    # --- PHẦN 2: GIẢI MÃ ---
    # Chọn menu 3: AuraTest
    r.recvuntil(b"What do you want to do little Beta?")
    r.sendlineafter(b"> ", b"3")

    # Nhận chuỗi đã mã hóa
    # Server in ra: "... decode this secret phrase: [ENCODED_STRING]"
    r.recvuntil(b"decode this secret phrase: ")
    encoded_line = r.recvline().decode().strip()
    
    print(f"[*] Encoded string: {encoded_line}")

    # Giải mã: Tìm tất cả các nhóm số (\d+) và thay thế bằng ký tự ASCII tương ứng
    # Các ký tự không phải số (chữ cái, khoảng trắng) giữ nguyên
    decoded_string = re.sub(
        r'(\d+)', 
        lambda m: chr(int(m.group(1))), 
        encoded_line
    )
    
    print(f"[+] Decoded string: {decoded_string}")

    # Gửi kết quả
    r.sendlineafter(b"> ", decoded_string.encode())

    # Nhận Flag
    r.interactive()

if __name__ == "__main__":
    solve()
from pwn import *
import re

# Cấu hình kết nối
HOST = 'auratester.ctf.pascalctf.it'
PORT = 7001

def solve():
    # Kết nối đến server
    print(f"[*] Connecting to {HOST}:{PORT}...")
    r = remote(HOST, PORT)

    # Nhập tên
    r.sendlineafter(b"> ", b"Hacker")

    # --- PHẦN 1: KIẾM AURA ---
    # Chọn menu 1: Trả lời câu hỏi
    r.sendlineafter(b"> ", b"1")

    # Trả lời 4 câu hỏi để đạt 700 điểm (YES, NO, YES, NO)
    # Câu 1: Do you believe in the power of aura? -> yes (+150)
    r.recvuntil(b"(yes/no)")
    r.sendline(b"yes")
    
    # Câu 2: Do you a JerkMate account? -> no (+50)
    r.recvuntil(b"(yes/no)")
    r.sendline(b"no")
    
    # Câu 3: Are you willing to embrace your inner alpha? -> yes (+450)
    r.recvuntil(b"(yes/no)")
    r.sendline(b"yes")
    
    # Câu 4: Do you really like SHYNE...? -> no (+50)
    r.recvuntil(b"(yes/no)")
    r.sendline(b"no")

    print("[+] Questions answered. Aura should be 700.")

    # --- PHẦN 2: GIẢI MÃ ---
    # Chọn menu 3: AuraTest
    r.recvuntil(b"What do you want to do little Beta?")
    r.sendlineafter(b"> ", b"3")

    # Nhận chuỗi đã mã hóa
    # Server in ra: "... decode this secret phrase: [ENCODED_STRING]"
    r.recvuntil(b"decode this secret phrase: ")
    encoded_line = r.recvline().decode().strip()
    
    print(f"[*] Encoded string: {encoded_line}")

    # Giải mã: Tìm tất cả các nhóm số (\d+) và thay thế bằng ký tự ASCII tương ứng
    # Các ký tự không phải số (chữ cái, khoảng trắng) giữ nguyên
    decoded_string = re.sub(
        r'(\d+)', 
        lambda m: chr(int(m.group(1))), 
        encoded_line
    )
    
    print(f"[+] Decoded string: {decoded_string}")

    # Gửi kết quả
    r.sendlineafter(b"> ", decoded_string.encode())

    # Nhận Flag
    r.interactive()

if __name__ == "__main__":
    solve()