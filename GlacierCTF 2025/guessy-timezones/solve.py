from pwn import *
import ctypes
import re

# 1. Thiết lập kết nối
# Nếu chạy local thì dùng process, remote thì dùng remote
host = 'challs.glacierctf.com'
port = 13386
p = remote(host, port)

# Load thư viện C chuẩn để dùng hàm rand() giống hệt server
libc = ctypes.CDLL('libc.so.6')

def solve():
    # Đợi menu hiện ra
    p.recvuntil(b'> ')
    
    # 2. Gửi lệnh lấy thời gian để lấy seed
    print("[*] Requesting time to leak seed...")
    p.sendline(b'time')
    p.recvuntil(b': ') # Hỏi múi giờ
    p.sendline(b'America/New_York') # Múi giờ nào cũng được miễn là có trong list

    # 3. Đọc phản hồi và lấy chuỗi thời gian
    # Server in ra: "THIS IS THE STRING: 20231123123045"
    response = p.recvuntil(b'THIS IS THE SEED').decode()
    
    # Dùng Regex để bắt chuỗi số sau "THIS IS THE STRING: "
    match = re.search(r"THIS IS THE STRING: (\d+)", response)
    if not match:
        print("[-] Error: Could not parse time string.")
        return

    time_str = match.group(1)
    print(f"[*] Time String leaked: {time_str}")
    
    # 4. Tính toán lại Seed và Winning Number
    # Chuyển string thành int
    full_value = int(time_str)
    
    # Trong C: srand((uint)uVar1);
    # Số 202411... lớn hơn 32bit nên sẽ bị tràn số. 
    # Ta mô phỏng ép kiểu bằng cách AND với 0xFFFFFFFF
    seed = full_value & 0xFFFFFFFF
    print(f"[*] Calculated Seed (uint): {seed}")
    
    # Gọi hàm C
    libc.srand(seed)
    winning_number = libc.rand()
    print(f"[*] Predicted Winning Number: {winning_number}")

    # 5. Gửi kết quả
    p.recvuntil(b'> ') # Menu lại hiện ra
    p.sendline(b'solve')
    
    p.recvuntil(b': ') # "Enter the magic number: "
    p.sendline(str(winning_number).encode())
    
    # 6. Nhận cờ
    result = p.recvall().decode()
    print("\n" + "="*20 + " RESULT " + "="*20)
    print(result)

if __name__ == "__main__":
    solve()