import random

# ================= INPUT ====================
# Dán chính xác 2 thông tin bạn vừa lấy được ở Bước 2 vào đây
THE_SEED_YOU_GAVE_ME = 1716113333  # <--- DÁN SEED CỦA BẠN VÀO ĐÂY
THE_VALUES_YOU_GAVE_ME = [96962807, 103060552, 91691093, 92675048, 99984508, 83608927, 105760795, 98953466, 113214240, 96556963, 98549665, 100633944, 93419781, 95983813, 108433451, 118900355, 98272562, 96844187, 97055640, 90612994, 101936253, 98307202, 89513884, 95467037, 99282935, 96288016, 92518815]

# Flag chính xác đã được dùng để tạo ra file test.txt
THE_ORIGINAL_FLAG = b"0160ca14{????????????????????????????????????}"
variable_list_original = list(THE_ORIGINAL_FLAG)
# ============================================

def scalar_multiplication(vector1, vector2):
    sum = 0
    for a, b in zip(vector1, vector2):
        sum += a * b
    return sum

# Bước 1: Dùng seed bạn cung cấp để tái tạo lại chính xác ma trận hệ số
print(f"[*] Sử dụng seed: {THE_SEED_YOU_GAVE_ME} để tái tạo hệ số...")
random.seed(THE_SEED_YOU_GAVE_ME)
coefficients_list_recreated = []
for i in range(27):
    coefficients = [random.randint(1, 2**16) for _ in range(len(THE_ORIGINAL_FLAG))]
    coefficients_list_recreated.append(coefficients)
print("[+] Đã tái tạo thành công ma trận hệ số.")

# Bước 2: Dùng ma trận vừa tái tạo và flag gốc để tính toán lại value_list
print("[*] Tính toán lại value_list để kiểm tra...")
value_list_calculated = []
for vector in coefficients_list_recreated:
    value = scalar_multiplication(vector, variable_list_original)
    value_list_calculated.append(value)
print("[+] Đã tính toán xong.")

# Bước 3: So sánh kết quả
print("[*] So sánh kết quả tính được với giá trị trong file test.txt...")
if value_list_calculated == THE_VALUES_YOU_GAVE_ME:
    print("\n========================================================")
    print("[SUCCESS] Hai value_list TRÙNG KHỚP HOÀN TOÀN!")
    print("=> Điều này CHỨNG MINH rằng: nếu biết ĐÚNG SEED, chúng ta có thể đảo ngược quá trình.")
    print("=> Logic giải bài của chúng ta là CHÍNH XÁC.")
    print("========================================================")
else:
    print("\n[FAILURE] Hai value_list KHÔNG TRÙNG KHỚP. Đã có lỗi ở đâu đó.")
    print("=> VUI LÒNG KIỂM TRA LẠI XEM BẠN ĐÃ COPY ĐÚNG SEED VÀ VALUE_LIST CHƯA.")