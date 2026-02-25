import sys

def solve_clean():
    try:
        with open("hidden_extracted.txt", "r", encoding="utf-8") as f:
            content = f.read()
    except FileNotFoundError:
        print("[-] Không tìm thấy file 'hidden_extracted.txt'.")
        return

    print("[+] Đang lọc bỏ nhiễu (LRO, PDF, IS...) và giữ lại ZWSP/ZWNJ/ZWJ...")

    # Chỉ giữ lại 3 thành phần cấu tạo nên bit
    valid_chars = [
        '\u200b', # ZWSP (Zero Width Space)
        '\u200c', # ZWNJ (Zero Width Non-Joiner)
        '\u200d'  # ZWJ  (Zero Width Joiner)
    ]
    
    # Lọc chuỗi
    clean_stream = [c for c in content if c in valid_chars]
    
    print(f"[+] Còn lại {len(clean_stream)} bit dữ liệu sạch (Đúng bằng 36 bytes).")

    # Xây dựng chuỗi nhị phân
    # Giả thuyết chuẩn: Ký tự xuất hiện nhiều nhất (ZWSP) là 0, còn lại là 1
    binary = ""
    for char in clean_stream:
        if char == '\u200b': # ZWSP
            binary += "0"
        else: # ZWNJ hoặc ZWJ
            binary += "1"

    # Hàm convert bin -> text
    def bin2text(b):
        chars = []
        for i in range(0, len(b), 8):
            byte = b[i:i+8]
            if len(byte) == 8:
                try:
                    chars.append(chr(int(byte, 2)))
                except: pass
        return "".join(chars)

    flag = bin2text(binary)
    print("\n" + "="*40)
    print(" FLAG CỦA BẠN LÀ:")
    print("="*40)
    print(flag)
    print("="*40)

    # Phòng hờ trường hợp đảo bit (ít xảy ra với bài này nhưng cứ check)
    if "BITS" not in flag and "CTF" not in flag:
        print("\n[!] Thử đảo bit (0 <-> 1)...")
        inverted_binary = binary.replace('0', 'x').replace('1', '0').replace('x', '1')
        print("Inverted Flag:", bin2text(inverted_binary))

if __name__ == "__main__":
    solve_clean()