import requests
import base64

# Hàm để XOR hai chuỗi byte
def xor(a, b):
    return bytes([x ^ y for x, y in zip(a, b)])

URL = "https://kerbal.sunshinectf.games"
s = requests.Session()

# Username đã được tính toán để đảm bảo độ dài plaintext không đổi sau khi thay đổi số moon
username = "s" 
print(f"[*] Đăng ký username: {username}")
s.post(URL, data={"name": username})

# Lấy cookie ban đầu (khi có 0 moon)
cookie_hex = s.cookies.get_dict()['clicker']
C_orig = bytes.fromhex(cookie_hex)
print(f"[*] Ciphertext gốc (0 moon): {C_orig.hex()}")


# --- SỬA LỖI PADDING Ở ĐÂY ---
# Hàm pad() mới: Đệm bằng byte null (\x00)
def pad(data, block_size=16):
    padding_len = block_size - (len(data) % block_size)
    # Nếu dữ liệu đã tròn khối, vẫn thêm một khối padding đầy đủ
    if padding_len == 0:
        padding_len = block_size
    return data + (b'\x00' * padding_len)
# -----------------------------


P_orig_str = f"{{'name':'{username}','moons':0}}"
P_target_str = f"{{'name':'{username}','moons':999999}}"

# Chuyển sang byte và thêm padding
P_orig = pad(P_orig_str.encode())
P_target = pad(P_target_str.encode())

# Kiểm tra lại độ dài
if len(P_orig) != len(P_target) or len(C_orig) != len(P_orig):
    print("[!] Lỗi: Độ dài không khớp!")
    print(f"    - Ciphertext gốc: {len(C_orig)} bytes")
    print(f"    - Plaintext gốc:   {len(P_orig)} bytes")
    print(f"    - Plaintext mục tiêu: {len(P_target)} bytes")
    exit()

print(f"[*] Plaintext gốc (đã đệm): {P_orig}")
print(f"[*] Plaintext mục tiêu (đã đệm): {P_target}")


# Tính toán ciphertext giả mạo
# C_target = C_orig XOR P_orig XOR P_target
xor_diff = xor(P_orig, P_target)
C_target = xor(C_orig, xor_diff)
print(f"[*] Ciphertext giả mạo: {C_target.hex()}")

# Gửi cookie giả mạo và lấy flag
new_cookie_value = C_target.hex()
new_cookies = {'clicker': new_cookie_value}
response = requests.get(URL, cookies=new_cookies)

# In ra phần text của response, flag sẽ ở trong đó
print("\n[+] Phản hồi từ server:")
if "sun{" in response.text:
    print("    FLAG FOUND!")
    print(response.text)
else:
    print("    Không tìm thấy flag, hãy kiểm tra lại logic.")
    print(response.text)