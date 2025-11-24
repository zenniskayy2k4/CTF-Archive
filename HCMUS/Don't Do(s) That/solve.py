import base64
ip = "192.168.0.22"
print("flag{" + base64.b64encode(ip.encode()).decode() + "}")