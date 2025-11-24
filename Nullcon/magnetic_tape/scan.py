import requests

base = "http://52.59.124.14:5005"
paths = [
    "/robots.txt", "/.env", "/health", "/status", "/debug", "/config",
    "/traceback", "/error", "/static/.env", "/static/config.py",
    "/backup", "/logs", "/api", "/api/config"
]

for p in paths:
    try:
        r = requests.get(base + p, timeout=5)
        print(f"{p:15s} → {r.status_code}")
        # Nếu response ngắn, hiển thị nội dung
        if r.status_code < 300 and len(r.text) < 500:
            print(r.text.strip(), "\n---")
    except Exception as e:
        print(f"{p:15s} → ERROR: {e}")
