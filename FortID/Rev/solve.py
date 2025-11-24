target_data = "<><<<>>=<>>=<>>><<>=<>>><><=<><<><=<><<<><=<>>>>=<<>><=<>><<<=<<>>=<>=<><>><=<<>><<<=<>>><>=<>>><<>=<>=<><><>>=<<>><=<>><=<>><=<<>><<=<>><<>=<<>><>=<>=<<>><><=<>><>>>=<>><<><=<>=<><<>><=<<>><=<>>><<>=<>><>>>=<>=<><>><=<<>><<<=<>>><>=<>>><<>=<>=<><<<>>=<>>><>=<>><>>>=<>><<><=<<>><><=<>><>>=<<>><=<>><>>>=<<>>=<<>><><=<<>><<=<>=<><><=<<>><=<>><<<=<>>><<>=<>><<=<>><><<=<>=<><<<<=<>><>><=<>><=<<>><<<=<>>><<>=<<>><<=<<>>=<>><><<=<>><>>=<<>><>=<>>>>>="

# Tách chuỗi target lớn thành các đường dẫn nhỏ cho mỗi ký tự flag
paths = target_data.split('=')

flag = ""

# Lặp qua mỗi đường dẫn cho từng ký tự
for path in paths:
    if not path:  # Bỏ qua các chuỗi rỗng
        continue

    # Bắt đầu mô phỏng lại tìm kiếm nhị phân
    low = 0
    high = 255

    # Đi theo các chỉ dẫn trong đường dẫn để thu hẹp phạm vi
    for step in path:
        mid = (low + high) // 2
        
        if step == '>':
            # Đoán quá thấp, tăng giới hạn dưới
            low = mid + 1
        elif step == '<':
            # Đoán quá cao, giảm giới hạn trên
            high = mid - 1
    
    # --- ĐÂY LÀ PHẦN SỬA LỖI ---
    # Ký tự chính xác là giá trị 'mid' sẽ được tính từ phạm vi [low, high] cuối cùng.
    # Đây là giá trị đã làm cho vòng lặp while trong C kết thúc.
    # Thay vì dùng chr(low), ta tính mid cuối cùng.
    final_char_code = (low + high) // 2
    flag += chr(final_char_code)

print(f"Flag: {flag}")