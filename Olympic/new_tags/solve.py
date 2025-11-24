import os
import re

# Thư mục chứa các tệp .trace
TRACE_DIR = '.'

def solve_new_tags(directory):
    file_data = []
    
    # Đọc tất cả các tệp .trace
    for filename in os.listdir(directory):
        if filename.endswith('.trace'):
            filepath = os.path.join(directory, filename)
            with open(filepath, 'rb') as f:
                content = f.read()
                file_data.append((filename, content))

    if not file_data:
        print("Không tìm thấy tệp .trace nào.")
        return

    # Sắp xếp các tệp dựa trên 4 byte đầu tiên (số thứ tự little-endian)
    try:
        sorted_files = sorted(file_data, key=lambda item: int.from_bytes(item[1][:4], 'little'))
        print(f"[*] Đã sắp xếp {len(sorted_files)} tệp.")
    except IndexError:
        print("Lỗi: Tệp không hợp lệ, không đủ 4 byte để sắp xếp.")
        return

    # Ghép nối nội dung (bỏ qua 4 byte đầu của mỗi tệp)
    reconstructed_data = b''
    for _, content in sorted_files:
        reconstructed_data += content[4:]
    
    print(f"[*] Đã ghép nối thành công dữ liệu.")

    # Lưu kết quả ra file .png
    output_filename = 'flag.png'
    with open(output_filename, 'wb') as f:
        f.write(reconstructed_data)
        
    print(f"[+] Dữ liệu đã được lưu vào file '{output_filename}'. Hãy mở file này để xem flag!")

if __name__ == "__main__":
    solve_new_tags(TRACE_DIR)