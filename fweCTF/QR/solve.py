import zlib

# Đọc dữ liệu từ file được binwalk trích xuất (thay '1EE' bằng tên file đúng)
with open('1EE.zlib', 'rb') as f:
    compressed_data = f.read()

# Giải nén dữ liệu
try:
    decompressed_data = zlib.decompress(compressed_data)
    # In ra dưới dạng text, hoặc ghi ra file mới
    print(decompressed_data.decode('utf-8', errors='ignore'))
    
    # Nếu nó là một file khác, hãy ghi ra
    with open('output_file', 'wb') as out_f:
        out_f.write(decompressed_data)
    print("\nĐã giải nén ra file 'output_file'")

except zlib.error as e:
    print(f"Lỗi giải nén Zlib: {e}")