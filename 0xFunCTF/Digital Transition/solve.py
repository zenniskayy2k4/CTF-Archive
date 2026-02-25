import numpy as np
from PIL import Image

with open('signal.bin', 'rb') as f:
    f.seek(16)
    data = f.read(1680000)

W, H = 800, 525
samples = np.frombuffer(data, dtype=np.uint8).reshape(H, W, 4)

# Lấy bit 2 của kênh 2 (tấm ảnh nét nhất bạn vừa gửi)
plane = (samples[:, :, 2] >> 2) & 1
res = (plane * 255).astype(np.uint8)
img = Image.fromarray(255 - res)

# KHÔNG CROP: Lưu toàn bộ ảnh để xem phần đầu 0XFUN{
img.save('flag.png')