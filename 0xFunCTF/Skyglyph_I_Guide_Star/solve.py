import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

# 1. Đọc dữ liệu
# Giả sử bạn đã lưu nội dung file vào 'tracker_dump.csv'
df = pd.read_csv('tracker_dump.csv')

# Tách sao dẫn đường (có tên) và sao mục tiêu (cần giải mã)
guides = df[df['name'].notna()].copy()
targets = df[df['name'].isna()].copy()

# 2. Xử lý toạ độ RA/Dec (Hệ toạ độ cầu)
# Xử lý vấn đề RA wrap (0h nối tiếp 24h)
# Các sao như Deneb (0.1h) thực tế nằm cạnh Vega (23.9h).
# Ta cộng 24 cho các sao có RA nhỏ để liền mạch.
guides['ra_adj'] = guides['ra_h'].apply(lambda x: x + 24 if x < 12 else x)

# Tính tâm của phép chiếu (Center of projection)
ra0 = np.deg2rad(guides['ra_adj'].mean() * 15) # Đổi giờ sang độ (*15) rồi sang radian
dec0 = np.deg2rad(guides['dec_deg'].mean())    # Đổi độ sang radian

# Hàm chiếu Gnomonic (Biến đổi Cầu -> Phẳng chuẩn)
def gnomonic_projection(ra_h, dec_deg, ra0, dec0):
    # Xử lý wrap cho từng điểm
    ra_adj = ra_h + 24 if ra_h < 12 else ra_h
    
    a = np.deg2rad(ra_adj * 15)
    d = np.deg2rad(dec_deg)
    
    cos_d = np.cos(d)
    sin_d = np.sin(d)
    cos_d0 = np.cos(dec0)
    sin_d0 = np.sin(dec0)
    
    # Delta RA
    da = a - ra0
    cos_da = np.cos(da)
    sin_da = np.sin(da)
    
    # Công thức chiếu
    denom = sin_d0 * sin_d + cos_d0 * cos_d * cos_da
    
    xi = (cos_d * sin_da) / denom
    eta = (cos_d0 * sin_d - sin_d0 * cos_d * cos_da) / denom
    
    return xi, eta

# Tính toạ độ phẳng chuẩn (xi, eta) cho các sao dẫn đường
coords = guides.apply(lambda row: gnomonic_projection(row['ra_h'], row['dec_deg'], ra0, dec0), axis=1, result_type='expand')
guides['xi'] = coords[0]
guides['eta'] = coords[1]

# 3. Tìm ma trận biến đổi (Calibration)
# Ta dùng hồi quy tuyến tính với các đặc trưng bậc 2 để khử méo (Radial distortion)
# Model: xi = c0 + c1*x + c2*y + c3*x^2 + c4*y^2 + c5*x*y
def get_features(x, y):
    return np.column_stack([
        np.ones(len(x)), x, y, x**2, y**2, x*y
    ])

# Huấn luyện mô hình trên các sao dẫn đường
X_train = get_features(guides['x_px'], guides['y_px'])
# Tìm hệ số chuyển đổi cho Xi và Eta
coeffs_xi, _, _, _ = np.linalg.lstsq(X_train, guides['xi'], rcond=None)
coeffs_eta, _, _, _ = np.linalg.lstsq(X_train, guides['eta'], rcond=None)

# 4. Áp dụng cho toàn bộ sao
X_all = get_features(targets['x_px'], targets['y_px'])
targets['xi_pred'] = X_all @ coeffs_xi
targets['eta_pred'] = X_all @ coeffs_eta

# 5. Vẽ hình và giải mã
plt.figure(figsize=(10, 6))

# Lọc bớt nhiễu bằng flux (đề bài gợi ý)
# Thử nghiệm cho thấy flux > 50-100 là đủ rõ, hoặc vẽ hết và chỉnh alpha
subset = targets[targets['flux'] > 150]

plt.scatter(subset['xi_pred'], subset['eta_pred'], s=10, c='black') # Tăng kích thước điểm s=10 cho dễ nhìn

# Đảo trục RA (vì RA tăng từ Đông sang Tây, ngược với trục X thông thường)
plt.gca().invert_xaxis() 
plt.xlim(reversed(plt.xlim()))

plt.title("Calibrated Skyglyph")
plt.xlabel("Standard Coordinate (Xi)")
plt.ylabel("Standard Coordinate (Eta)")
plt.axis('equal') # Giữ tỉ lệ khung hình chuẩn để chữ không bị bẹt
plt.show()