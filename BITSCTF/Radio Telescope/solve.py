import numpy as np
import matplotlib.pyplot as plt

# 1. Tải dữ liệu
data = np.loadtxt('rt7-log.txt')
xs = data[0::3]
ys = data[1::3]
zs = data[2::3]
m = min(len(xs), len(ys), len(zs))
xs, ys, zs = xs[:m], ys[:m], zs[:m]

# 2. Tạo một dải các lớp cắt (Slices) theo trục Z
# Vì flag là "khoảng trống", chúng ta sẽ vẽ các điểm thật nhỏ
# để nhìn thấy cái "lỗ" ở giữa.
fig, axes = plt.subplots(2, 4, figsize=(20, 10))
axes = axes.flatten()

# Chia dải Z thành 8 phần để tìm xem Flag nằm ở tầng nào
z_slices = np.linspace(np.min(zs), np.max(zs), 9)

for i in range(8):
    mask = (zs >= z_slices[i]) & (zs < z_slices[i+1])
    axes[i].scatter(xs[mask], ys[mask], s=0.5, c='black', alpha=0.7)
    axes[i].set_title(f"Z-Slice {i+1}")
    axes[i].set_aspect('equal')

plt.tight_layout()
plt.show()