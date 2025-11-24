import time
import random
from datetime import datetime, timezone
from z3 import Solver, Int, sat

# 1. Đọc dữ liệu từ file output.txt
try:
    with open("output.txt", "r") as f:
        content = f.read()
    value_list_str = content.split("= ")[1]
    value_list = eval(value_list_str)
except FileNotFoundError:
    print("[-] Lỗi: Không tìm thấy file 'output.txt'. Hãy đảm bảo nó nằm cùng thư mục với script này.")
    exit()

# 2. Định nghĩa các thông tin đã biết về flag
FLAG_LEN = 46
FLAG_PREFIX = b"0160ca14{"
FLAG_SUFFIX = b"}"

# 3. Xác định khoảng thời gian để brute-force seed (timestamp)
# Giả định "11:26 AM" là giờ địa phương Việt Nam (UTC+7).
# Quy đổi sang UTC: 11:26 (UTC+7) -> 04:26 (UTC).
# Chúng ta sẽ tìm kiếm trong một khoảng rộng hơn một chút, ví dụ từ 4:25 đến 4:28 UTC.
start_time_utc = datetime(2025, 5, 15, 4, 25, 0, tzinfo=timezone.utc)
end_time_utc = datetime(2025, 5, 15, 4, 28, 0, tzinfo=timezone.utc)

start_seed = int(start_time_utc.timestamp())
end_seed = int(end_time_utc.timestamp())

print(f"[*] Giả định thời gian '11:26 AM' là giờ Việt Nam (UTC+7).")
print(f"[*] Quy đổi sang UTC: tìm kiếm xung quanh 04:26 AM UTC.")
print(f"[*] Bắt đầu tìm kiếm seed trong khoảng timestamp [{start_seed}, {end_seed}]")

found = False
# 4. Vòng lặp Brute-force seed
for seed in range(start_seed, end_seed):
    current_time_str = datetime.fromtimestamp(seed, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
    print(f"\r[*] Đang thử seed: {seed} ({current_time_str} UTC)", end="")

    random.seed(seed)
    coefficients_list = []
    for i in range(27):
        coefficients = [random.randint(1, 2**16) for _ in range(FLAG_LEN)]
        coefficients_list.append(coefficients)

    s = Solver()
    flag_vars = [Int(f"f_{i}") for i in range(FLAG_LEN)]

    # Ràng buộc prefix, suffix và ký tự in được
    for i, char_code in enumerate(FLAG_PREFIX):
        s.add(flag_vars[i] == char_code)
    s.add(flag_vars[FLAG_LEN - 1] == ord(FLAG_SUFFIX))
    for i in range(len(FLAG_PREFIX), FLAG_LEN - 1):
        s.add(flag_vars[i] >= 32, flag_vars[i] <= 126)

    # Thêm 27 phương trình
    for i in range(len(value_list)):
        equation = sum(coefficients_list[i][j] * flag_vars[j] for j in range(FLAG_LEN))
        s.add(equation == value_list[i])

    if s.check() == sat:
        print(f"\n[+] Đã tìm thấy seed hợp lệ: {seed} ({current_time_str} UTC)")
        model = s.model()
        flag_bytes = bytes([model[var].as_long() for var in flag_vars])
        flag = flag_bytes.decode('ascii')
        print(f"\n[*] FLAG: {flag}\n")
        found = True
        break

if not found:
    print("\n[-] Không tìm thấy seed. Có thể giả định về múi giờ (UTC+7) không đúng hoặc khoảng thời gian tìm kiếm cần được mở rộng.")