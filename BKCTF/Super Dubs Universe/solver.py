import os
from collections import Counter
import base64

print("[+] Bắt đầu thuật toán Toạ độ (Geometric Outlier)...")

# 1. Đọc tất cả 200 frames
frames = []
for i in range(1, 201):
    txt_path = f"frames/level{i}.txt"
    if os.path.exists(txt_path):
        with open(txt_path, "r", encoding="utf-8") as f:
            frames.append(f.readlines())

if not frames:
    print("Không tìm thấy file txt nào.")
    exit()

num_rows = len(frames[0])

print("[+] Bước 1: Khôi phục hình nền gốc (Xoá hoàn toàn con cú khỏi nền)...")
bg = []
for r in range(num_rows):
    row_bg = []
    max_c = max(len(f[r]) if r < len(f) else 0 for f in frames)
    for c in range(max_c):
        chars = []
        for f in frames:
            if r < len(f) and c < len(f[r]):
                chars.append(f[r][c])
        if chars:
            row_bg.append(Counter(chars).most_common(1)[0][0])
        else:
            row_bg.append(' ')
    bg.append("".join(row_bg))

print("[+] Bước 2: Truy vết chính xác toạ độ Base64 bị giấu...")
b64_string = ""
b64_alphabet = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
owl_chars = set("W\\/|- ")

for i, f in enumerate(frames):
    diffs = []
    for r in range(len(f)):
        for c in range(len(f[r])):
            bg_char = bg[r][c] if r < len(bg) and c < len(bg[r]) else ' '
            if f[r][c] != bg_char and f[r][c] not in ('\n', '\r'):
                diffs.append((r, c, f[r][c]))
    
    if not diffs:
        continue
        
    # Tìm tâm của cụm nhiễu (vị trí con cú đang đứng)
    r_coords = sorted([d[0] for d in diffs])
    c_coords = sorted([d[1] for d in diffs])
    median_r = r_coords[len(r_coords)//2]
    median_c = c_coords[len(c_coords)//2]
    
    best_char = ""
    max_dist = -1
    
    # Tìm ký tự nằm cách xa trung tâm con cú nhất (Outlier)
    for (r, c, char) in diffs:
        if char not in b64_alphabet:
            continue
            
        dist = abs(r - median_r) + abs(c - median_c)
        if dist > max_dist:
            max_dist = dist
            best_char = char
            
    # Dự phòng: Nếu xui xẻo ký tự giấu nằm chìm ngay trong cánh con cú
    if max_dist < 10:
        for (r, c, char) in diffs:
            if char in b64_alphabet and char not in owl_chars:
                best_char = char
                break
                
    if best_char:
        b64_string += best_char

print("\nBase64:")
print(b64_string)

try:
    # Padding thêm dấu = để decode không bị lỗi nếu thừa/thiếu
    b64_padded = b64_string + "=" * ((4 - len(b64_string) % 4) % 4)
    decoded = base64.b64decode(b64_padded).decode('utf-8', errors='ignore')
    
    # Lọc lấy đoạn chứa format cờ
    if "bkctf{" in decoded:
        flag = decoded[decoded.find("bkctf{"):decoded.find("}")+1]
        print("Flag: " + flag)
    else:
        print(decoded)
except Exception as e:
    print("Vui lòng copy chuỗi trên lên CyberChef để decode nhé!")