def extract_tlsb(file_path):
    with open(file_path, 'rb') as f:
        # File BMP của bạn có bits offset là 54
        f.seek(54)
        data = f.read()
    
    extracted_bits = ""
    for byte in data:
        # Lấy bit thứ 3 (bit index 2): (byte >> 2) & 1
        bit = (byte >> 2) & 1
        extracted_bits += str(bit)
    
    # Chuyển chuỗi bit thành ký tự ASCII
    flag = ""
    for i in range(0, len(extracted_bits), 8):
        byte_str = extracted_bits[i:i+8]
        if len(byte_str) == 8:
            # Lưu ý: Có thể cần đảo ngược chuỗi bit tùy theo cách giấu
            flag += chr(int(byte_str, 2))
    
    return flag

print(extract_tlsb("TLSB"))
