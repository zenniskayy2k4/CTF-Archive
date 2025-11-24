from pwn import *

# Thay đổi HOST và PORT nếu cần
# HOST = "localhost"
# PORT = 5000 
# ví dụ: HOST = "challenge.ctf.games", PORT = 31234
HOST = "vm.daotao.antoanso.org" 
PORT = 33055

# Kết nối tới server
p = remote(HOST, PORT)

# Nhận dòng "100" đầu tiên
p.recvline()

responses = []

# Thực hiện 7 lượt hỏi để lấy 7 bit
for i in range(7):
    # Tạo chuỗi query cho bit thứ i
    # query[k] = (k >> i) & 1
    query = ""
    for k in range(100):
        if (k >> i) & 1:
            query += "1"
        else:
            query += "0"

    log.info(f"Querying for bit {i}...")
    # Gửi '?' để bắt đầu hỏi
    p.sendlineafter(b'>', b'?')
    # Gửi chuỗi query
    p.sendline(query.encode())

    # Nhận và lưu kết quả
    response = p.recvline().strip().decode()
    responses.append(response)

log.success("Collected all 7 bit-responses.")

# Tái tạo lại hoán vị gốc
permutation = [0] * 100
for i in range(100):
    reconstructed_val = 0
    for j in range(7):
        # Lấy bit từ các response
        bit = int(responses[j][i])
        # Ghép bit vào đúng vị trí
        reconstructed_val |= (bit << j)
    
    # Giá trị thực sự là (giá trị tái tạo) + 1
    permutation[i] = reconstructed_val + 1

log.info("Reconstructed permutation:")
print(permutation)

# Chuyển mảng hoán vị thành chuỗi để gửi đi
answer_str = ' '.join(map(str, permutation))

# Gửi '!' để bắt đầu trả lời
p.sendlineafter(b'>', b'!')
# Gửi đáp án
log.info("Sending the final answer...")
p.sendline(answer_str.encode())

# Nhận flag
p.interactive()