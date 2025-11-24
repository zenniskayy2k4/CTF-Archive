from PIL import Image

# Tạo một ảnh grayscale 2x2
width, height = 2, 2
img = Image.new('L', (width, height))

# Đặt giá trị pixel: trắng (255), đen (0)
# (0,0) (1,0)
# (0,1) (1,1)
pixels = [
    255, 0,  # Hàng đầu tiên
    0, 255   # Hàng thứ hai
]
img.putdata(pixels)

# Lưu lại với tên flag.png để script X.py có thể đọc
img.save("flag.png")

print("Đã tạo file 'flag.png' mẫu (2x2) thành công.")