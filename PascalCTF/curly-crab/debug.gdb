# Load chương trình
file ./curly-crab

# Đặt breakpoint tại hàm main của crate (không phải hàm main của C)
# Dựa vào code của bạn, tên hàm là curly_crab::main
break curly_crab::main

# Đặt breakpoint tại hàm parse để đếm số lần nó được gọi
break curly_crab::parse

# Chạy chương trình
run

# Khi dừng lại ở main, chúng ta sẽ xem nó chạy như thế nào.
# Tiếp tục chạy để xem nó hit breakpoint parse bao nhiêu lần.
continue
