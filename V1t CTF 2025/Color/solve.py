import cv2

def solve_color_challenge_final(image_path):
    img = cv2.imread(image_path)
    img_rgb = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
    
    # 1. Tìm hàng Y chứa dải màu
    y_coord = -1
    for y in range(img_rgb.shape[0]):
        # Một hàng hợp lệ là hàng có chứa cả pixel màu và pixel không phải màu (nền xám)
        row = img_rgb[y, :]
        is_gray_present = any(p[0] == p[1] and p[1] == p[2] for p in row)
        is_color_present = any(not (p[0] == p[1] and p[1] == p[2]) for p in row)
        if is_gray_present and is_color_present:
            y_coord = y
            break
            
    if y_coord == -1: return "Lỗi: Không tìm thấy hàng dữ liệu."

    # 2. Trích xuất các nhóm số được phân tách bởi màu Đen/Trắng
    groups = []
    current_group = []
    x = 0
    while x < img_rgb.shape[1]:
        r, g, b = img_rgb[y_coord, x]
        current_color = (r, g, b)
        
        # Bỏ qua màu nền xám (giả sử có giá trị từ 1 đến 254)
        if r == g and g == b and 0 < r < 255:
            x += 1
            continue
        
        # Đo chiều rộng của khối màu hiện tại
        width = 0
        temp_x = x
        while temp_x < img_rgb.shape[1] and tuple(img_rgb[y_coord, temp_x]) == current_color:
            width += 1
            temp_x += 1
        
        is_separator = (r < 10 and g < 10 and b < 10) or (r > 240 and g > 240 and b > 240)
        
        if is_separator:
            # Nếu gặp dấu phân cách (Đen/Trắng), hoàn thành nhóm hiện tại
            if current_group:
                groups.append(current_group)
                current_group = []
        else:
            # Nếu là màu khác, thêm chiều rộng vào nhóm hiện tại
            current_group.append(width)
        
        x = temp_x # Di chuyển con trỏ đến khối tiếp theo
        
    # Thêm nhóm cuối cùng nếu có
    if current_group:
        groups.append(current_group)
        
    # 3. Tính tổng mỗi nhóm để tạo flag
    flag = ""
    for group in groups:
        char_code = sum(group)
        flag += chr(char_code)
        
    return flag

# Chạy hàm giải mã
final_flag = solve_color_challenge_final("c0l0r.png")
print(final_flag)