import time
import random
from Crypto.Util.number import bytes_to_long
from datetime import datetime, timezone

FLAG = b"0160ca14{????????????????????????????????????}"
variable_list = list(FLAG)

def scalar_multiplication(vector1, vector2):
    assert len(vector1) == len(vector2), "Two vectors must have the same dimension!"
    sum = 0
    for a,b in zip(vector1, vector2):
        sum += a*b

    return sum


seed = int(time.time())
# === CÁC DÒNG LỆNH THÊM VÀO ĐỂ IN THÔNG TIN ===
# Chuyển đổi timestamp (seed) sang đối tượng thời gian UTC
human_readable_time_utc = datetime.fromtimestamp(seed, tz=timezone.utc)
# In ra seed và thời gian UTC tương ứng
print(f"[*] Seed (timestamp) được sử dụng: {seed}")
print(f"[*] Thời gian tương ứng (UTC): {human_readable_time_utc.strftime('%Y-%m-%d %H:%M:%S %Z')}")
# =======================================================
random.seed(seed)

coefficients_list = []
for i in range(27):
    coefficients = []
    
    for j in range(len(FLAG)):
        coefficients.append(random.randint(1, 2**16))

    coefficients_list.append(coefficients)        


value_list = []
for vector in coefficients_list:
    value_list.append(scalar_multiplication(vector, variable_list))



with open("test.txt", "w") as file:
    file.write(f"{value_list = }")