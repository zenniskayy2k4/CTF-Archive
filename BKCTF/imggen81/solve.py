import math
from collections import Counter

def solve():
    print("[*] Đang đọc file flag.raw...")
    with open("flag.raw", "rb") as f:
        data = f.read()

    print("[*] BƯỚC 1: Dùng Delta Method triệt tiêu Hash 8-byte...")
    # D[i] = Data[i] ^ Data[i+8]. Bước này xóa sổ hoàn toàn mã Hash!
    D = bytearray(len(data) - 8)
    for i in range(len(data) - 8):
        D[i] = data[i] ^ data[i+8]

    print("[*] BƯỚC 2: Truy tìm chiều dài thật của Prompt...")
    best_L = 0
    max_score = 0
    best_Pr_diff = []

    # Quét độ dài Prompt từ 4 đến 150 ký tự
    for L in range(4, 150):
        score = 0
        Pr_diff = bytearray(L)
        for i in range(L):
            chunk = D[i::L]
            if len(chunk) > 0:
                most_common, count = Counter(chunk).most_common(1)[0]
                Pr_diff[i] = most_common
                score += count
        if score > max_score:
            max_score = score
            best_L = L
            best_Pr_diff = Pr_diff

    print(f"[+] Tìm thấy chiều dài Prompt thực sự L = {best_L}")

    print("[*] BƯỚC 3: Giải mã ngược để lấy nguyên văn câu Prompt...")
    g = math.gcd(8, best_L)
    true_prompt = bytearray(best_L)
    Pr_prime = bytearray(best_L)
    
    # Phân rã chuỗi để tìm ra Text ASCII
    for c in range(g):
        Pr_prime[c] = 0
        curr = c
        while True:
            next_idx = (curr + 8) % best_L
            if next_idx == c: break
            Pr_prime[next_idx] = Pr_prime[curr] ^ best_Pr_diff[curr]
            curr = next_idx
            
        best_C = 0
        best_ascii = -1
        # Tìm hằng số C để dịch ngược ra chữ cái in được (Alphanumeric)
        for C_guess in range(256):
            ascii_score = 0
            curr = c
            while True:
                val = Pr_prime[curr] ^ C_guess
                if 32 <= val <= 126:
                    ascii_score += 1
                    if chr(val).isalnum(): ascii_score += 2
                curr = (curr + 8) % best_L
                if curr == c: break
            if ascii_score > best_ascii:
                best_ascii = ascii_score
                best_C = C_guess
        
        curr = c
        while True:
            true_prompt[curr] = Pr_prime[curr] ^ best_C
            curr = (curr + 8) % best_L
            if curr == c: break
                
    try:
        print(f"\n[!] TÌM THẤY PROMPT CỦA TÁC GIẢ: \033[93m{true_prompt.decode('ascii')}\033[0m\n")
    except:
        pass

    print("[*] BƯỚC 4: Lột trần lớp mã hóa kép và kết xuất ảnh...")
    # Bóc lớp Prompt
    C2 = bytearray(len(data))
    for i in range(len(data)):
        C2[i] = data[i] ^ true_prompt[i % best_L]

    # Bóc lớp Hash
    H_prime = bytearray(8)
    for i in range(8):
        chunk = C2[i::8]
        H_prime[i] = Counter(chunk).most_common(1)[0][0]

    decrypted = bytearray(len(data))
    for i in range(len(data)):
        decrypted[i] = C2[i] ^ H_prime[i % 8]

    try:
        from PIL import Image
        img = Image.frombytes('L', (320, 200), bytes(decrypted))
        
        # Tiling 2x2 để phần chữ bị cắt tự động nối lại ở tâm ảnh
        tiled_img = Image.new('L', (640, 400))
        tiled_img.paste(img, (0, 0))
        tiled_img.paste(img, (320, 0))
        tiled_img.paste(img, (0, 200))
        tiled_img.paste(img, (320, 200))
        
        tiled_img.save("ULTIMATE_PERFECT.png")
        print("[+] Đã lưu 'ULTIMATE_PERFECT.png'. Bức ảnh này là sự hoàn hảo tuyệt đối!")
    except Exception as e:
        print(f"[-] Lỗi lưu ảnh (hãy cài Pillow): {e}")

if __name__ == "__main__":
    solve()