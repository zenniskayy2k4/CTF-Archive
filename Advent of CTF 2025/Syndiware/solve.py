def decode_diary(filename):
    print(f"[*] Đang giải mã {filename}...")
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            content = f.read()
    except FileNotFoundError:
        print("[-] Không tìm thấy file. Hãy tạo file text chứa nội dung số.")
        return

    # Xóa các ký tự không phải số và khoảng trắng thừa
    content = content.replace('\n', ' ').replace('\r', '')
    
    # Tách thành các khối 8 số
    blocks = content.split(' ')
    decoded_text = ""

    for block in blocks:
        if len(block) < 8: continue # Bỏ qua các khối lỗi
        
        # Xác định loại mã hóa dựa trên ký tự đầu
        binary_str = ""
        if '6' in block or '7' in block:
            # Elf67: 6=0, 7=1
            binary_str = block.replace('6', '0').replace('7', '1')
        elif '4' in block or '1' in block:
            # Elf41: 4=0, 1=1
            binary_str = block.replace('4', '0').replace('1', '1')
        
        # Chuyển nhị phân sang ký tự
        try:
            char_code = int(binary_str, 2)
            decoded_text += chr(char_code)
        except:
            pass

    print("\n--- NỘI DUNG GIẢI MÃ ---\n")
    print(decoded_text)
    print("\n------------------------\n")
    
    # Tìm kiếm Flag trong nội dung
    if "csd" in decoded_text or "flag" in decoded_text.lower():
        print("[!] PHÁT HIỆN FLAG TIỀM NĂNG!")
        # In ra đoạn chứa flag
        index = decoded_text.lower().find("flag")
        if index == -1: index = decoded_text.find("csd")
        start = max(0, index - 20)
        end = min(len(decoded_text), index + 100)
        print(f"snippet: ...{decoded_text[start:end]}...")

# HƯỚNG DẪN:
# 1. Mở file PDF đã giải mã (ví dụ Elf67's Diary.pdf).
# 2. Copy toàn bộ nội dung (Ctrl+A, Ctrl+C).
# 3. Paste vào một file tên là 'diary_67.txt' cùng thư mục với script này.
# 4. Chạy script.

if __name__ == "__main__":
    # Bạn hãy tạo file diary_67.txt và paste số vào đó
    decode_diary("diary_67.txt")