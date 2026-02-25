from PIL import Image

def apply_arnold_cat_map(img, s, spins):
    width, height = img.size
    N = width
    
    current_img = img.copy()
    
    for _ in range(spins):
        # Tạo ảnh mới trống (mặc định nền đen) để hứng các pixel được di chuyển
        new_img = Image.new(current_img.mode, current_img.size)
        pixels = current_img.load()
        new_pixels = new_img.load()
        
        for x in range(N):
            for y in range(N):
                # Công thức Arnold's Cat Map
                nx = (x + s * y) % N
                ny = (s * nx + y) % N
                
                # ĐÂY LÀ DÒNG QUAN TRỌNG NHẤT ĐÃ ĐƯỢC SỬA: 
                # Chuyển pixel từ tọa độ (x, y) cũ sang tọa độ (nx, ny) mới
                new_pixels = pixels
                
        current_img = new_img
        
    return current_img

if __name__ == "__main__":
    print("Reading image...")
    # Đọc ảnh gốc (chú mèo origami)
    img = Image.open('transmission.png')

    # THỰC HIỆN XÁO TRỘN THEO ĐÚNG TRÌNH TỰ ĐỂ HIỆN FLAG
    # Bước 1: style = 1, lặp 47 lần
    print("Applying Step 1 (style=1, spins=47)...")
    img = apply_arnold_cat_map(img, 1, 47)

    # Bước 2: style = 2, lặp 37 lần
    print("Applying Step 2 (style=2, spins=37)...")
    img = apply_arnold_cat_map(img, 2, 37)

    # Bước 3: style = 1, lặp 29 lần
    print("Applying Step 3 (style=1, spins=29)...")
    img = apply_arnold_cat_map(img, 1, 29)

    # Lưu lại ảnh kết quả
    img.save('flag_revealed.png')
    print("Success! Please check 'flag_revealed.png'.")