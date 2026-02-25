import os

print("[+] Bắt đầu trích xuất ký tự ẩn...")

# Đọc frame 1 làm chuẩn (bản gốc chưa bị thay đổi)
with open("frames/level1.txt", "r", encoding="utf-8") as f:
    base_lines = f.readlines()

hidden_string = ""

for i in range(2, 201): # So sánh từ frame 2 đến 200
    txt_path = f"frames/level{i}.txt"
    if not os.path.exists(txt_path):
        continue
        
    with open(txt_path, "r", encoding="utf-8") as f:
        frame_lines = f.readlines()
        
    diff_char = ""
    # So sánh từng dòng của frame hiện tại với base frame
    for line_idx in range(min(len(base_lines), len(frame_lines))):
        line_base = base_lines[line_idx]
        line_frame = frame_lines[line_idx]
        
        if line_base != line_frame:
            # Nếu dòng có sự khác biệt, tìm chính xác ký tự nào thay đổi
            for char_idx in range(min(len(line_base), len(line_frame))):
                if line_base[char_idx] != line_frame[char_idx]:
                    diff_char = line_frame[char_idx]
                    break
        if diff_char:
            break # Tìm thấy 1 ký tự rồi thì qua frame tiếp theo
            
    if diff_char:
        print(f"Frame {i:03}: Tìm thấy '{diff_char}'")
        hidden_string += diff_char

print("\n[!] Chuỗi thu được:", hidden_string)