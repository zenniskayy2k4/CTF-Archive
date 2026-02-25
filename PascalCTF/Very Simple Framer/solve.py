from PIL import Image
import sys

def solve():
    # Đường dẫn đến file ảnh cần giải mã trong workspace của bạn
    # Dựa trên file search, file có thể là output.jpg
    image_path = "output.jpg" 
    
    try:
        img = Image.open(image_path)
        img = img.convert("RGB")
    except FileNotFoundError:
        print(f"Không tìm thấy file {image_path}. Hãy chắc chắn bạn đã tải ảnh về hoặc đổi tên đúng trong code.")
        return

    width, height = img.size
    print(f"[*] Image size: {width}x{height}")

    # Tạo lại danh sách tọa độ viền theo đúng logic của chal.py
    coords = []
    
    # 1. Viền trên (Trái -> Phải)
    for x in range(width):
        coords.append((x, 0))
    
    # 2. Viền phải (Trên -> Dưới)
    for y in range(1, height - 1):
        coords.append((width - 1, y))
    
    # 3. Viền dưới (Phải -> Trái)
    if height > 1:
        for x in range(width - 1, -1, -1):
            coords.append((x, height - 1))
    
    # 4. Viền trái (Dưới -> Trên)
    if width > 1:
        for y in range(height - 2, 0, -1):
            coords.append((0, y))

    # Duyệt qua các pixel viền để lấy bit
    binary_str = ""
    for x, y in coords:
        r, g, b = img.getpixel((x, y))
        # Tính độ sáng trung bình để xử lý nhiễu JPEG
        brightness = (r + g + b) // 3
        
        # Nếu sáng (gần trắng) -> 1, Tối (gần đen) -> 0
        if brightness > 128:
            binary_str += "1"
        else:
            binary_str += "0"

    # Chuyển nhị phân thành ký tự
    message = ""
    # Cắt chuỗi binary thành từng cụm 8 bit (1 byte)
    for i in range(0, len(binary_str), 8):
        byte = binary_str[i:i+8]
        if len(byte) < 8:
            break
        try:
            char_code = int(byte, 2)
            # Chỉ lấy các ký tự in được để output đỡ rác
            if 32 <= char_code <= 126: 
                message += chr(char_code)
            else:
                message += '_' # Ký tự không đọc được
        except:
            pass
            
    print(f"[*] Extracted data (snippet): {message[:200]}")
    
    # Tìm Flag trong chuỗi
    if "pascalCTF{" in message:
        print("\n[+] FOUND FLAG:")
        # Cắt lấy đoạn chứa flag
        start = message.find("pascalCTF{")
        end = message.find("}", start)
        if end != -1:
            print(message[start:end+1])
        else:
            print(message[start:])
    else:
        print("\n[-] Flag format not found clearly. Check the extracted data above.")

if __name__ == "__main__":
    solve()