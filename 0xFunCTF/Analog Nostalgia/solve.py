import numpy as np
from PIL import Image

OFFSET_START = 21
# Tổng số mẫu dựa trên vị trí file ZIP
TOTAL_SAMPLES = (2100025 - OFFSET_START) // 5 

with open('signal.bin', 'rb') as f:
    f.seek(OFFSET_START)
    # Đọc chính xác lượng dữ liệu mẫu
    raw_data = f.read(TOTAL_SAMPLES * 5)

# Tách thành các cột R, G, B (bỏ qua 2 cột Sync tạm thời)
samples = np.frombuffer(raw_data, dtype=np.uint8).reshape(-1, 5)
rgb_data = samples[:, :3].astype(np.uint16) # Dùng uint16 để tránh overflow khi nhân

# Tăng độ sáng (Normalize)
# Vì 0x20 (~32) là rất tối, ta nhân để đưa nó lên vùng nhìn thấy được
rgb_data = rgb_data * 6 
rgb_data[rgb_data > 255] = 255
rgb_data = rgb_data.astype(np.uint8)

# Thử nghiệm với chiều rộng chuẩn của VGA (bao gồm lề)
# Thông thường là 800 cho độ phân giải 640x480
WIDTH = 800 
HEIGHT = TOTAL_SAMPLES // WIDTH

# Cắt bớt để vừa khít mảng
final_data = rgb_data[:WIDTH*HEIGHT].reshape((HEIGHT, WIDTH, 3))

img = Image.fromarray(final_data)
img.save('flag.png')