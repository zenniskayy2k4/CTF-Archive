from hashlib import sha512

# Đọc chuỗi hash đầu tiên từ file
try:
    with open("final_hashes_full.txt", "r") as f:
        first_hash_from_pcap = f.readline().strip()
except FileNotFoundError:
    print("Lỗi: Không tìm thấy file 'final_hashes_full.txt'. Hãy chạy lại script 'extract_all.py'.")
    exit()

pad = b"XfilTr4T3_"
assumed_pixel_value = b"255" # Giả định pixel đầu tiên là màu trắng

# Danh sách các từ khóa có khả năng cao nhất
wordlist = ["secret", "secrets", "key", "flag", "xfiltrate", "friend", "funny"]

print(f"Hash mục tiêu (từ pcap): {first_hash_from_pcap}")
print("Bắt đầu brute-force tìm tiền tố bí mật...")

found_key = None
for word in wordlist:
    secret_prefix = word.encode()
    
    # Tính toán hash thử nghiệm
    test_hash_obj = sha512(secret_prefix + pad + assumed_pixel_value)
    test_hash_hex = test_hash_obj.hexdigest()
    
    print(f"  Thử với key '{word}' -> Hash: {test_hash_hex[:20]}...")
    
    # So sánh
    if test_hash_hex == first_hash_from_pcap:
        found_key = word
        break

if found_key:
    print(f"\n!!! KEY ĐÃ ĐƯỢC TÌM THẤY: '{found_key}' !!!")
else:
    print("\n[!] Không tìm thấy key trong wordlist. Giả định có thể sai.")