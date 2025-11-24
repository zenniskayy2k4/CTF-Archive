from z3 import *

s = Solver()

x_digits = [Int(f'x_{i}') for i in range(8)]
y_digits = [Int(f'y_{i}') for i in range(7)]

# Ràng buộc cơ bản cho các chữ số
s.add(x_digits[0] >= 1, x_digits[0] <= 9)
for i in range(1, 8):
    s.add(x_digits[i] >= 0, x_digits[i] <= 9)

s.add(y_digits[0] >= 1, y_digits[0] <= 9)
for i in range(1, 7):
    s.add(y_digits[i] >= 0, y_digits[i] <= 9)

# Tái tạo số x và y từ các chữ số
x_val = Sum([x_digits[i] * (10**(7-i)) for i in range(8)])
y_val = Sum([y_digits[i] * (10**(6-i)) for i in range(7)])

# --- GIẢ ĐỊNH QUAN TRỌNG ĐỂ TĂNG TỐC ---
# Giả định rằng từ tích thứ 2 trở đi, tất cả các tích con đều bằng 0
# Điều này có nghĩa là x[2:] hoặc y[1:] sẽ toàn là số 0
# Ví dụ: x=12000000, y=8912345 hoặc x=1234567, y=8000000
for i in range(1, 7):
    s.add(x_digits[i+1] * y_digits[i] == 0)
# ----------------------------------------

# Tái tạo dream_val dựa trên giả định trên
p0 = x_digits[1] * y_digits[0]

# Logic xây dựng dream_val đã được sửa lỗi:
# dream_val được tạo bằng cách ghép: x_0 || p0 || 0 || 0 || 0 || 0 || 0 || 0
# Vì các tích sau p0 đều bằng 0, nên phần còn lại của chuỗi là 6 số 0.

# Nếu p0 có 1 chữ số (p0 < 10):
# dream_val = x_0 * 10^7 + p0 * 10^6
# Ví dụ: x_0=1, p0=2 -> "1" + "2" + "000000" -> 12000000

# Nếu p0 có 2 chữ số (p0 >= 10):
# dream_val = x_0 * 10^8 + p0 * 10^6
# Ví dụ: x_0=1, p0=16 -> "1" + "16" + "000000" -> 116000000

dream_val = If(p0 < 10,
               x_digits[0] * 10**7 + p0 * 10**6,
               x_digits[0] * 10**8 + p0 * 10**6)

# Thêm điều kiện chính
s.add(dream_val == x_val * y_val)

# Thêm điều kiện phụ (nếu cần, nhưng có thể bỏ qua để solver dễ tìm hơn)
s.add(x_val * y_val != 381404224402842)

# Tìm lời giải
print("Solving with corrected optimized constraints...")
if s.check() == sat:
    m = s.model()
    x_result = m.eval(x_val).as_long()
    y_result = m.eval(y_val).as_long()
    print("Found solution:")
    print(f"x = {x_result}")
    print(f"y = {y_result}")
else:
    print("No solution found with these constraints.")