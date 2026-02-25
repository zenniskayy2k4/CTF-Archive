import cv2
import numpy as np
import matplotlib.pyplot as plt

# 1. Tái tạo dữ liệu từ Haze (thử dải từ 7 đến 100)
img = cv2.imread('challenge_stego.tif', cv2.IMREAD_UNCHANGED)
U, S, V = np.linalg.svd(img, full_matrices=False)
S_haze = np.zeros_like(S)
S_haze[7:100] = S[7:100] 
img_haze = U @ np.diag(S_haze) @ V
haze_norm = cv2.normalize(img_haze, None, 0, 255, cv2.NORM_MINMAX)
_, binary = cv2.threshold(np.uint8(haze_norm), 0, 255, cv2.THRESH_BINARY | cv2.THRESH_OTSU)

# 2. Resampling về lưới 21x21 (QR Version 1)
grid_size = 21
module_size = binary.shape[0] / grid_size
qr_data = np.zeros((grid_size, grid_size), dtype=np.uint8)

for i in range(grid_size):
    for j in range(grid_size):
        module_roi = binary[int(i*module_size):int((i+1)*module_size), int(j*module_size):int((j+1)*module_size)]
        qr_data[i, j] = 0 if np.mean(module_roi) < 127 else 255

def build_perfect_qr(data_grid):
    grid = data_grid.copy()
    
    # Hàm vẽ Finder Pattern kèm Separator (vùng trắng bao quanh)
    def draw_finder_with_separator(g, y, x):
        # Vẽ Separator (khối trắng 9x9 hoặc 8x8 tùy góc)
        y_start, y_end = max(0, y-1), min(21, y+8)
        x_start, x_end = max(0, x-1), min(21, x+8)
        g[y_start:y_end, x_start:x_end] = 255
        # Vẽ Finder (7x7 đen, 5x5 trắng, 3x3 đen)
        g[y:y+7, x:x+7] = 0
        g[y+1:y+6, x+1:x+6] = 255
        g[y+2:y+5, x+2:x+5] = 0

    # Vẽ cấu trúc chuẩn
    draw_finder_with_separator(grid, 0, 0)   # Top-Left
    draw_finder_with_separator(grid, 0, 14)  # Top-Right
    draw_finder_with_separator(grid, 14, 0)  # Bottom-Left
    
    # Timing patterns
    for i in range(8, 13):
        grid[6, i] = 0 if i % 2 == 0 else 255
        grid[i, 6] = 0 if i % 2 == 0 else 255

    # Thêm Quiet Zone chuẩn (4 module trắng bao quanh)
    final = cv2.copyMakeBorder(grid, 4, 4, 4, 4, cv2.BORDER_CONSTANT, value=255)
    return cv2.resize(final, (400, 400), interpolation=cv2.INTER_NEAREST)

# Tạo 2 bản: Bình thường và Đảo ngược dữ liệu
# (SVD thường làm đảo màu nên bản Inverted thường là bản đúng)
qr_standard = build_perfect_qr(qr_data)
qr_inverted_data = build_perfect_qr(255 - qr_data)

fig, ax = plt.subplots(1, 2, figsize=(12, 6))
ax[0].imshow(qr_standard, cmap='gray')
ax[0].set_title("Standard Data")
ax[1].imshow(qr_inverted_data, cmap='gray')
ax[1].set_title("Inverted Data (Try this!)")
plt.show()