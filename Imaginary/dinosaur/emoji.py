from PIL import Image

# Đọc tất cả các từ vào một danh sách
with open('STEGosaurus.txt', 'r') as f:
    words = f.read().split()

num_columns = 7
reordered_words = []
num_words = len(words)

# Sắp xếp lại các từ bằng cách đọc theo cột
for i in range(num_columns):
    for j in range(i, num_words, num_columns):
        reordered_words.append(words[j])

# Tạo chuỗi nhị phân từ danh sách từ đã được sắp xếp lại
binary_string = ""
for word in reordered_words:
    if 'i' in word:
        binary_string += '1'
    else:
        binary_string += '0'

# Chiều rộng của ảnh vẫn là 332
width = 332
# Bỏ đi các bit thừa không đủ để tạo một hàng hoàn chỉnh
height = len(binary_string) // width
binary_string = binary_string[:width * height]

# Tạo ảnh mới từ chuỗi nhị phân ĐÚNG
img = Image.new('1', (width, height))
pixels = img.load()

for y in range(height):
    for x in range(width):
        pixel_value = int(binary_string[y * width + x])
        pixels[x, y] = 0 if pixel_value == 1 else 1 # Thử đảo ngược màu (0=đen, 1=trắng) để dễ đọc hơn

# Lưu ảnh kết quả
img.save('flag_final.png')

print("Đã tạo ảnh flag_final.png! Đây là kết quả cuối cùng.")