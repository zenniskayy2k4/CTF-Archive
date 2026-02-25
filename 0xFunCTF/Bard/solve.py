import base64
data = base64.b64decode(open('bits.txt').read())
# Tạo chữ ký PNG chuẩn
png_signature = b'\x89PNG\r\n\x1a\n'
# Tạo tên chunk IHDR chuẩn
ihdr_tag = b'IHDR'

# Ghi đè vào dữ liệu đã giải mã
data_fixed = bytearray(data)
data_fixed[0:8] = png_signature   # Sửa 8 byte đầu
data_fixed[12:16] = ihdr_tag      # Sửa tên chunk đầu tiên thành IHDR

# Lưu thành file ảnh
with open('flag.png', 'wb') as f:
    f.write(data_fixed)