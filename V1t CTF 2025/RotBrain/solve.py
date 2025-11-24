import zlib

# Hàm thực hiện phép XOR
def xor(data, key):
    return bytes([b ^ key for b in data])

try:
    # Bước 1: Mở file và trích xuất dữ liệu từ các khối IDAT (giống như trước)
    with open('image.png', 'rb') as f:
        content = f.read()

    compressed_data = b''
    offset = 0
    while True:
        idat_pos = content.find(b'IDAT', offset)
        if idat_pos == -1:
            break
        
        # Lấy độ dài khối dữ liệu từ 4 byte đứng trước 'IDAT'
        length_bytes = content[idat_pos-4:idat_pos]
        length = int.from_bytes(length_bytes, 'big')
        
        # Trích xuất và ghép nối dữ liệu
        data_start = idat_pos + 4
        data_end = data_start + length
        compressed_data += content[data_start:data_end]
        
        offset = data_end

    if not compressed_data:
        raise ValueError("Không tìm thấy dữ liệu trong các khối IDAT.")

    print(f"Đã trích xuất {len(compressed_data)} bytes. Bắt đầu brute-force XOR key...")

    # Bước 2: Brute-force key XOR một byte (từ 0 đến 255)
    found = False
    for key in range(256):
        try:
            # XOR toàn bộ dữ liệu nén với key hiện tại
            xor_data = xor(compressed_data, key)

            # Cố gắng giải nén dữ liệu đã được XOR
            decompressed_data = zlib.decompress(xor_data)

            # Nếu không có lỗi, chúng ta đã tìm thấy key đúng!
            print(f"\n[+] THÀNH CÔNG! Tìm thấy key XOR là: {key} (dạng hex: 0x{key:02x})")
            
            # Giải mã và in ra nội dung ẩn
            hidden_text = decompressed_data.decode('utf-8', errors='ignore')
            print("\n--- NỘI DUNG ĐƯỢC GIẢI NÉN ---")
            print(hidden_text)
            print("-----------------------------\n")

            found = True
            break  # Thoát khỏi vòng lặp vì đã tìm thấy kết quả

        except zlib.error:
            # Nếu giải nén lỗi, đây không phải key đúng. Tiếp tục thử key tiếp theo.
            continue

    if not found:
        print("Không tìm thấy key XOR hợp lệ. Dữ liệu có thể bị mã hóa theo cách khác.")

except FileNotFoundError:
    print("Lỗi: Không tìm thấy file 'image.png'.")
except Exception as e:
    print(f"Đã xảy ra lỗi không xác định: {e}")