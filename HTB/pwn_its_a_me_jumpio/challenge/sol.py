from pwn import *

# Context cho biết đây là binary 64-bit của Linux
context.update(arch='amd64', os='linux')

HOST = '94.237.54.192'
PORT = 56360

# Dùng pwnlib.tubes.remote.remote thay vì remote
p = remote(HOST, PORT)

# Lần đầu tiên, chúng ta cần nhận prompt ban đầu
p.recvuntil(b'Press \'W\' to jump and collect coins!')

log.info("Collecting 10 coins...")
for i in range(10):
    log.info(f"Sending 'w' character #{i+1}")
    
    p.send(b'w')
    
    # Sau 9 lần đầu, chúng ta vẫn nhận lại prompt cũ
    if i < 9:
        p.recvuntil(b'Press \'W\' to jump and collect coins!')
    # Sau lần thứ 10, chương trình sẽ vào shop, nên chúng ta không đợi prompt cũ nữa

# Bây giờ, stdin của server đã sạch, không còn ký tự thừa.
# Server đã gửi menu shop. Chúng ta đợi nó.
log.info("Waiting for the shop menu...")
p.recvuntil(b'1337)')

# Bây giờ chương trình dùng fgets, nó cần một dòng hoàn chỉnh -> Dùng sendline()
log.info("Choosing option 2 (Pink Roses)")
p.sendline(b'2')

# Đợi câu hỏi số lượng
p.recvuntil(b'How many bouquets?')

# Gửi số lượng. Vẫn là line-buffered.
log.info("Choosing to buy 1 bouquet")
p.sendline(b'1')

# Nhận flag
log.info("Receiving the flag...")
# Dùng recvall với timeout để chắc chắn script kết thúc
flag = p.recvall(timeout=2) 
print(flag.decode(errors='ignore'))

p.close()