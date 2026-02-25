import re

def extract_hidden_bits(filepath):
    with open(filepath, 'r') as f:
        data = f.read()
    
    # Tìm các giá trị X trong lệnh "X 0 Td"
    # Chỉ lấy các giá trị có sai số (kết thúc bằng 7988 hoặc 8293)
    coords = re.findall(r'(\d+\.\d+)\s+0\s+Td', data)
    
    bits = ""
    for c in coords:
        if "7988" in c:
            bits += "0"
        elif "8293" in c:
            bits += "1"
    
    # Chuyển bit thành ký tự
    decoded = ""
    for i in range(0, len(bits), 8):
        byte = bits[i:i+8]
        if len(byte) == 8:
            decoded += chr(int(byte, 2))
    
    # Đảo ngược chuỗi theo logic "Mushroom"
    return decoded[::-1]

print(f"Mảnh tìm được: {extract_hidden_bits('2C466.txt')}")