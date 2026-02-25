from pwn import *
import hashlib
import base64

# Cấu hình
HOST = 'dum-cows.ctf.prgy.in'
PORT = 1337

def solve():
    print("[*] Đang kết nối tới server...")
    io = remote(HOST, PORT, ssl=True)
    
    # 1. Gửi Input dài 64 bytes
    # Input này sẽ chiếm trọn vẹn 4 chuỗi hash: MD5(d), MD5(dd), MD5(ddd), MD5(dddd)
    my_input = b"a" * 64
    
    io.recvuntil(b"Give your cow a name:")
    io.sendline(my_input)
    
    # Nhận phản hồi
    io.recvuntil(b"[Name: ")
    enc_name_b64 = io.recvuntil(b"]", drop=True)
    io.recvuntil(b"says: ")
    enc_msg_b64 = io.recvline().strip()
    
    # 2. Lấy mẫu Key (Signature)
    enc_name = base64.b64decode(enc_name_b64)
    enc_msg = base64.b64decode(enc_msg_b64)
    
    # KeyStream thực tế của block đầu tiên
    full_key_name = xor(my_input, enc_name)
    first_block_key = full_key_name[:16]
    
    print(f"[+] Sample Key Block (Hex): {first_block_key.hex()}")
    
    # 3. Tìm con số bí mật (The Digit)
    found_digit = None
    
    # Dò từ 0 đến 9
    for i in range(10):
        digit_char = str(i)
        # Tính MD5 của số đó
        h = hashlib.md5(digit_char.encode()).digest()
        
        if h == first_block_key:
            found_digit = digit_char
            print(f"[!] BINGO! Quy luật là lặp lại số: '{found_digit}'")
            break
            
    if not found_digit:
        print("[-] Không tìm thấy digit 0-9. Có thể là chữ cái? Thử chạy lại script.")
        io.close()
        return

    # 4. Tạo Key để giải mã Message
    # Message nằm sau 64 bytes input -> Tức là bắt đầu từ Block số 5 (index 4 nếu đếm từ 0)
    # Quy luật: Block k tương ứng với MD5(digit * (k+1))
    
    # Message cần block 5, block 6, block 7...
    # Tức là: MD5("44444"), MD5("444444")...
    
    key_stream_msg = b""
    
    # Tạo dự phòng 5 block (đủ cho message dài 80 ký tự)
    start_repeat = 5 # Vì input đã dùng hết 1,2,3,4 lần lặp
    for i in range(5):
        repeat_count = start_repeat + i
        seed_string = found_digit * repeat_count # Ví dụ: "44444"
        
        # Hash MD5
        key_stream_msg += hashlib.md5(seed_string.encode()).digest()
        
    # 5. Giải mã và Lấy Flag
    decrypted_msg = xor(enc_msg, key_stream_msg[:len(enc_msg)])
    
    print("\n" + "="*40)
    print(f"[RESULT] Decrypted Message: {decrypted_msg}")
    print("="*40)
    
    io.close()

if __name__ == "__main__":
    solve()