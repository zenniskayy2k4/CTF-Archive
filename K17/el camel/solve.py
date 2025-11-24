from pwn import *

# context.log_level = 'debug'
conn = remote('challenge.secso.cc', 7001)

# Bỏ qua các dòng giới thiệu
conn.recvuntil(b'prize...\n\n')

p = int(conn.recvline().strip())
q = int(conn.recvline().strip())

print(f"Received p = {p}")
print(f"Received q = {q}")

# Chọn và gửi m0, m1
m0 = 0
m1 = 1

conn.sendlineafter(b'How tall do you want the coin to be?> ', str(m0).encode())
conn.sendlineafter(b'How long do you want the coin to be?> ', str(m1).encode())

# Vòng lặp game
for i in range(50):
    print(f"\n--- Round {i+1}/50 ---")
    
    line = conn.recvline().strip()
    # Nếu dòng đọc được là dòng trống (từ vòng 2 trở đi), đọc dòng tiếp theo để lấy c
    if not line:
        line = conn.recvline().strip()
        
    c = int(line)
    print(f"Received c = {c}")

    # Logic kiểm tra vẫn giữ nguyên
    k_candidate_0 = c
    
    if pow(k_candidate_0, q, p) == 1:
        guess = 'H'
        print("Test for H passed. Guessing H.")
    else:
        guess = 'T'
        print("Test for H failed. Guessing T.")

    # Gửi dự đoán sau khi nhận được prompt "> "
    # sendlineafter sẽ đọc "The coin has been tossed..."
    conn.sendlineafter(b'Heads or Tails! (H or T)> ', guess.encode())
    
    # In kết quả
    result = conn.recvline().strip().decode()
    print(f"Result: {result}")

conn.interactive()
conn.close()