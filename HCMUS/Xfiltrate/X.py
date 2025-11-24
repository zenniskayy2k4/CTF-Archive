from PIL import Image
from hashlib import sha512
from binascii import hexlify

# --- Các hàm và biến từ file gốc ---
pad = b"XfilTr4T3_"

def encrypt1(m):
  return sha512(pad + str(m).encode()).hexdigest()

# Chúng ta không cần encrypt2 cho phân tích này
# def encrypt2(m): ...

# --- Mở ảnh mẫu và chạy logic ---
try:
    image = Image.open("flag.png").convert("L")
except FileNotFoundError:
    print("Lỗi: Không tìm thấy file 'flag.png'. Hãy chạy script 'create_test_flag.py' trước.")
    exit()

width, height = image.size
print(f"Đang phân tích ảnh mẫu '{'flag.png'}' kích thước {width}x{height}...")
print("-" * 30)

# Chỉ chạy cho nửa trên của ảnh (trong trường hợp này là toàn bộ ảnh 2x2)
for y in range(height):
  for x in range(width):
    pix = image.getpixel((x, y))
    print(f"Pixel ({x},{y}) có giá trị: {pix}")
    
    c = encrypt1(pix)
    print(f"  -> Hash SHA-512: {c}")
    
    # Mô phỏng việc cắt và "gửi" đi
    print("  -> Các mảnh dữ liệu được tạo ra:")
    for i in range(0, len(c), 50):
      chunk = c[i:i + 50]
      print(f"     - {chunk}")
    print("-" * 30)