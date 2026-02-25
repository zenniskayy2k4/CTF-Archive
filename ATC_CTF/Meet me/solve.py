import hashlib

target_hash = "6d6a1730ab3407ac463cd737b3ba7d68d492d2b22f6c858fb1a6ba90e5bb2b46"
target_hash = "6d6a1730ab3407ac463cd737b3ba7d68d492d2b22f6c858fb1a6ba90e5bb2b46"

try:
    with open("Meetme.txt", "r", encoding="utf-8") as f:
        lines = f.readlines()

    for i, line in enumerate(lines):
        # Quan trọng: Cắt bỏ ký tự xuống dòng (\n) ở cuối mỗi dòng
        clean_line = line.strip()
        
        # Tạo hash SHA256
        generated_hash = hashlib.sha256(clean_line.encode('utf-8')).hexdigest()
        
        # So sánh
        if generated_hash == target_hash:
            print("\n---------------- FOUND! ----------------")
            print(f"Line number {i+1}:")
            print(clean_line)
            print(f"Hash: {generated_hash}")
            break
    else:
        print("\nNo matching line found. Please check the input file (encoding, line endings).")

except FileNotFoundError:
    print("File Meetme.txt not found.")