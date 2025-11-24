from scapy.all import *
from scapy.layers.http import HTTPRequest
import re

# Đọc file pcap
packets = rdpcap('wegogym.pcap')

current_reps = 0
flag = ""

print("Dang giai ma du lieu theo logic Gym (Reps ^ Weight)...")

# Duyệt qua từng gói tin
for p in packets:
    if p.haslayer(HTTPRequest):
        try:
            uri = p[HTTPRequest].Path.decode('utf-8')
            
            # Nếu là GET / thì tăng biến đếm (Reps)
            if uri == "/" or uri == "":
                current_reps += 1
            
            # Nếu gặp file noise thì thực hiện giải mã
            elif "noise" in uri:
                # Lấy số trong tên file (Weight)
                match = re.search(r'noise(\d+)\.txt', uri)
                if match:
                    weight = int(match.group(1))
                    
                    # Công thức: Char = Weight XOR Reps
                    # (Lưu ý: Có thể cần điều chỉnh +1/-1 tùy vào cách server đếm, nhưng XOR là chuẩn nhất cho CTF)
                    char_code = weight ^ current_reps
                    
                    decoded_char = chr(char_code)
                    flag += decoded_char
                    
                    # In chi tiết để debug
                    print(f"Noise: {weight} | Reps: {current_reps} -> Char: {decoded_char}")
                    
                    # Reset biến đếm cho hiệp tập tiếp theo
                    current_reps = 0
        except Exception as e:
            continue

print("\n--------------------------------")
print("FLAG FULL:", flag)
print("--------------------------------")