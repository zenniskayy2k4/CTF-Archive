import zipfile
import os
import shutil
import time

# Tạo thư mục chứa pdf và txt
os.makedirs("frames", exist_ok=True)
current_file = "level1.jpg"

print("[+] Bước 1: Bắt đầu tự động giải nén 200 levels...")
for i in range(1, 201):
    if not os.path.exists(current_file):
        break
    
    # Copy và đổi đuôi sang .pdf
    pdf_path = f"frames/level{i}.pdf"
    shutil.copy(current_file, pdf_path)
    
    # Giải nén để lấy level tiếp theo
    try:
        with zipfile.ZipFile(current_file, 'r') as z:
            z.extractall()
            current_file = f"level{i+1}.jpg"
    except Exception:
        # Nếu không còn file zip bên trong, vòng lặp sẽ dừng
        break

print("[+] Bước 2: Trích xuất nội dung PDF sang TXT...")
# Trên Linux bạn có thể cài bằng: sudo apt-get install poppler-utils
for i in range(1, 201):
    pdf_path = f"frames/level{i}.pdf"
    txt_path = f"frames/level{i}.txt"
    if os.path.exists(pdf_path):
        os.system(f"pdftotext -layout {pdf_path} {txt_path}")

print("[+] Bước 3: Phát Animation trên Terminal sau 3 giây...")
time.sleep(3)
for i in range(1, 201):
    txt_path = f"frames/level{i}.txt"
    if os.path.exists(txt_path):
        os.system('clear') # Dùng lệnh 'cls' nếu bạn đang chạy trên Windows
        with open(txt_path, "r", encoding="utf-8") as f:
            print(f.read())
        print(f"--- Frame {i} / 200 ---")
        time.sleep(0.15) # Delay 0.15s cho mỗi khung hình