from pwn import *
import sys

# Script Python "Chống đạn"
# 1. Chặn stderr để tránh gửi Traceback sang C
# 2. Xử lý chuỗi ID an toàn (xóa dấu chấm)
# 3. Flush stdout liên tục
exploit_script = r'''
import sys
import os

# QUAN TRỌNG: Chặn stderr. Nếu script lỗi, nó sẽ gửi EOF thay vì Traceback text.
sys.stderr = open(os.devnull, 'w')

def safe_get_id(line):
    # Line: "You are player number 13. You have..."
    try:
        parts = line.split()
        if "number" in parts:
            idx = parts.index("number")
            # Lấy phần tử sau chữ "number", xóa dấu chấm nếu có
            num_str = parts[idx+1].replace('.', '')
            return int(num_str)
    except:
        pass
    return 0

def solve():
    # 1. Đọc prompt đầu tiên để lấy ID
    # C gửi: "You are player number X..."
    first_line = sys.stdin.readline()
    if not first_line: return
    
    my_id = safe_get_id(first_line)
    
    # Chiến thuật: Hộp đầu tiên mở là hộp trùng ID của mình
    next_box = my_id
    
    while True:
        # Gửi số hộp muốn mở
        print(next_box)
        sys.stdout.flush() # Bắt buộc flush để C nhận được ngay
        
        # Đọc kết quả: "FOUND <val>"
        response = sys.stdin.readline()
        if not response: break
        
        if "FOUND" in response:
            try:
                # Lấy số trong hộp
                found_val = int(response.strip().split()[1])
                # Số trong hộp trỏ đến hộp tiếp theo cần mở
                next_box = found_val
            except:
                break
        
        # Đọc prompt tiếp theo: "You are player number..."
        # C luôn gửi dòng này trước mỗi lần nhập liệu
        try:
            sys.stdin.readline()
        except:
            break

if __name__ == "__main__":
    try:
        solve()
    except:
        sys.exit(0)
'''

def run_solver():
    attempt = 0
    while True:
        attempt += 1
        print(f"[*] Attempt {attempt}...", end=' ')
        
        r = None
        try:
            r = remote('chall.polygl0ts.ch', 6667, level='error')
            
            # Đếm số người chơi đã qua
            players_passed = 0
            
            while True:
                # Đợi tín hiệu từ server
                # - 'script': Yêu cầu nộp code
                # - 'failed': Thất bại
                # - '}': Flag
                output = r.recvuntil([b'script', b'failed', b'}'], timeout=15)
                
                if not output:
                    print(" Disconnected.")
                    break
                
                if b'script' in output:
                    # Gửi code exploit
                    r.sendline(exploit_script.encode())
                    r.sendline(b'EOF')
                    
                    players_passed += 1
                    # In tiến độ (mỗi 10 người chơi in số 1 lần cho gọn)
                    if players_passed % 10 == 0:
                        print(f"{players_passed}", end='', flush=True)
                    else:
                        print(".", end='', flush=True)

                elif b'failed' in output:
                    # Thua, thử lại từ đầu
                    print(f" Failed at player {players_passed}. Retrying.")
                    break
                
                elif b'}' in output:
                    # Có thể flag đã nằm trong output hoặc còn nằm trong buffer
                    full_output = output + r.recvall(timeout=2)
                    print("\n\n[+] SUCCESS! FLAG:")
                    print(full_output.decode(errors='ignore'))
                    return

        except KeyboardInterrupt:
            print("\nStopped.")
            return
        except Exception as e:
            print(f" Error: {e}")
        finally:
            if r: r.close()

if __name__ == "__main__":
    run_solver()