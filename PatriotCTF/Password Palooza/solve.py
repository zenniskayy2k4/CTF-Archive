import hashlib

# Hash cần tìm
target_hash = "3a52fc83037bd2cb81c5a04e49c048a2"
wordlist_path = "rockyou.txt" # Đảm bảo bạn đã tải file này về

print("Đang chạy brute-force...")

try:
    with open(wordlist_path, "r", encoding="latin-1") as f:
        for line in f:
            base_pass = line.strip()
            
            # Thử ghép với 2 số từ 00 đến 99
            for i in range(100):
                # Format số thành 2 chữ số (ví dụ 5 -> "05")
                suffix = f"{i:02d}" 
                candidate = base_pass + suffix
                
                # Tạo hash MD5
                candidate_hash = hashlib.md5(candidate.encode()).hexdigest()
                
                if candidate_hash == target_hash:
                    print(f"\n[+] Tìm thấy mật khẩu: {candidate}")
                    print(f"[+] Flag: pctf{{{candidate}}}")
                    exit()
except FileNotFoundError:
    print("Không tìm thấy file rockyou.txt")