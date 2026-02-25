import urllib.request
import time

print("[*] Đang tải từ điển tiếng Anh chuẩn (10.000 từ phổ biến)...")
url = "https://raw.githubusercontent.com/first20hours/google-10000-english/master/google-10000-english-no-swears.txt"
req = urllib.request.Request(url)
with urllib.request.urlopen(req) as response:
    # Tải danh sách từ và làm sạch
    words = response.read().decode('utf-8').splitlines()
    words = list(set([w.lower().strip() for w in words if w.isalpha()]))

print(f"[+] Tải xong {len(words)} từ. Bắt đầu ghép chữ theo gợi ý 'bkctf'...\n")

def check_pattern(text):
    # Cấu trúc: A B c b E F G k B F b I A
    if len(text) != 13: 
        return False
    # Ráp các chữ c, b, k bạn tìm được vào đúng vị trí
    if text[2] != 'c' or text[3] != 'b' or text[7] != 'k' or text[10] != 'b': 
        return False
    # Kiểm tra các ký hiệu trùng nhau
    if text[0] != text[12]: return False  # A = A
    if text[1] != text[8]: return False   # B = B
    if text[5] != text[9]: return False   # F = F
    return True

start_time = time.time()

# 1. Thử xem có phải là 1 từ dài 13 chữ cái không
for w in words:
    if check_pattern(w):
        print(f"[!!!] BINGO (1 TỪ): {w}")

# 2. Thử xem có phải là 2 từ viết liền nhau không (Ví dụ: "the flagis...")
print("[*] Đang tìm các cụm 2 từ viết liền...")
words_filtered = [w for w in words if len(w) < 13]
for w1 in words_filtered:
    for w2 in words_filtered:
        combo = w1 + w2
        if len(combo) == 13 and check_pattern(combo):
            print(f"[!!!] BINGO (2 TỪ): {w1} {w2}")

# 3. Thử xem có phải là 3 từ ghép lại không
print("[*] Đang tìm các cụm 3 từ viết liền (Mất khoảng 2-3 giây)...")
# Tối ưu hóa: từ thứ 3 phải có chứa chữ 'b' ở vị trí tương ứng
for w1 in [w for w in words_filtered if len(w) <= 8]:
    for w2 in [w for w in words_filtered if len(w) <= 8 - len(w1) + 5]:
        combo_2 = w1 + w2
        if len(combo_2) >= 13: continue
        
        # Chỉ lấy các từ thứ 3 sao cho độ dài tổng = 13
        len_w3 = 13 - len(combo_2)
        valid_w3 = [w for w in words_filtered if len(w) == len_w3]
        
        for w3 in valid_w3:
            combo = combo_2 + w3
            if check_pattern(combo):
                print(f"[!!!] BINGO (3 TỪ): {w1} {w2} {w3}")

print(f"\n[+] Script hoàn thành trong {time.time() - start_time:.2f} giây!")