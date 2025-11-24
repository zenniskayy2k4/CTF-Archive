import os
from pathlib import Path
from itertools import cycle

TARGET_DIR = Path("./recipes/")

# !!! DÁN KHÓA BẠN TÌM ĐƯỢC TỪ SCRIPT find_key.py VÀO ĐÂY !!!
# Ví dụ, nếu key là 010203... thì viết là:
# KEY = bytes.fromhex("010203...")
# Dưới đây là một key giả định, bạn phải thay thế nó
KEY = bytes.fromhex("268f76ad1431f132879fcb6c0e704b99")

if not KEY:
    print("Vui lòng cập nhật biến KEY trong script với khóa bạn đã tìm thấy.")
    exit()

def decrypt(file: Path, key: bytes) -> None:
    # Đảm bảo chúng ta chỉ giải mã các file .enc
    if not file.name.endswith(".enc"):
        return

    with open(file, "rb") as f:
        ciphertext = f.read()

    # Thuật toán giải mã y hệt thuật toán mã hóa
    plaintext = bytes(a ^ b for a, b in zip(ciphertext, cycle(key)))

    # Tạo tên file gốc bằng cách bỏ đuôi .enc
    original_file_path = file.with_suffix('')
    
    with open(original_file_path, "wb") as f:
        f.write(plaintext)

    print(f"Decrypted {file.name} -> {original_file_path.name}")

if __name__=="__main__":
    print("Decrypting files...")
    for file in TARGET_DIR.rglob("*.enc"):
        if file.is_file():
            decrypt(file, KEY)
    print("\nDecryption complete!")