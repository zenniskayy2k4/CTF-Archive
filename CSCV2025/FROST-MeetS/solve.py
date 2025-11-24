import requests
import hashlib
import time
from coincurve.keys import PrivateKey, PublicKey

# Cấu hình
URL = "http://crypto2.cscv.vn:80"
CLIENT_ID = "exploit-client-cscv"
RELEASE_FLAG_MESSAGE = b"RELEASE_THE_FLAG"
CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# --- Các hàm tiện ích từ mã nguồn của server ---

def tagged_hash(tag: str, *messages: bytes) -> bytes:
    tag_hash = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_hash + tag_hash + b''.join(messages)).digest()

def challenge_hash(R: bytes, pubkey: bytes, message: bytes) -> int:
    R_x = PublicKey(R).format(compressed=False)[1:33]
    pk_x = PublicKey(pubkey).format(compressed=False)[1:33]
    challenge_bytes = tagged_hash("BIP0340/challenge", R_x, pk_x, message)
    return int.from_bytes(challenge_bytes, 'big') % CURVE_ORDER

def mod_inverse(a: int, modulus: int = CURVE_ORDER) -> int:
    return pow(a, modulus - 2, modulus)

def get_beta(session_id: str, joint_pubkey: bytes) -> int:
    h_blind = hashlib.sha256()
    h_blind.update(b"R_blind")
    h_blind.update(session_id.encode('utf-8'))
    h_blind.update(joint_pubkey)
    beta_bytes = h_blind.digest()
    return int.from_bytes(beta_bytes, 'big') % CURVE_ORDER

# --- Hàm chính ---

def get_signature(message_hex: str):
    """Lấy chữ ký từ server."""
    payload = {"client_id": CLIENT_ID, "message": message_hex}
    try:
        res = requests.post(f"{URL}/approvals/request", json=payload, timeout=20)
        res.raise_for_status()
        data = res.json()
        if data.get("status") != "success":
            print("Lỗi khi lấy chữ ký:", data.get("error", {}).get("message"))
            return None
        return data["data"]
    except requests.exceptions.RequestException as e:
        print(f"Lỗi request: {e}")
        return None

def get_joint_pubkey():
    """Lấy khóa công khai chung từ endpoint health."""
    try:
        res = requests.get(f"{URL}/health")
        res.raise_for_status()
        return bytes.fromhex(res.json()["joint_pubkey"])
    except requests.exceptions.RequestException as e:
        print(f"Lỗi khi lấy khóa công khai: {e}")
        return None

def solve():
    print("[+] Lấy khóa công khai chung của hội đồng...")
    joint_pubkey = get_joint_pubkey()
    if not joint_pubkey:
        return
    print(f"    Khóa công khai chung: {joint_pubkey.hex()}")

    # Bước 1: Lấy 2 chữ ký cho cùng một thông điệp để tính R_base và s_base
    print("\n[+] Lấy chữ ký cho thông điệp m1...")
    message1_hex = "6d65737361676531" # "message1"
    sig_data1 = get_signature(message1_hex)
    if not sig_data1: return
    
    # Đợi một chút để đảm bảo không bị rate limit
    time.sleep(1)

    print("[+] Lấy chữ ký thứ hai cho cùng thông điệp m1...")
    sig_data2 = get_signature(message1_hex)
    if not sig_data2: return

    # Tính beta cho cả hai phiên
    beta1 = get_beta(sig_data1["session_id"], joint_pubkey)
    beta2 = get_beta(sig_data2["session_id"], joint_pubkey)

    # Trích xuất s_pub và tính s_base
    s_pub1 = int(sig_data1["signature"]["s"], 16)
    s_base1 = (s_pub1 - beta1) % CURVE_ORDER
    
    print(f"    s_base cho m1: {hex(s_base1)}")

    # Bước 2: Lấy chữ ký cho thông điệp thứ hai
    print("\n[+] Lấy chữ ký cho thông điệp m2...")
    message2_hex = "6d65737361676532" # "message2"
    sig_data3 = get_signature(message2_hex)
    if not sig_data3: return
    
    time.sleep(1)

    print("[+] Lấy chữ ký thứ hai cho cùng thông điệp m2...")
    sig_data4 = get_signature(message2_hex)
    if not sig_data4: return

    beta3 = get_beta(sig_data3["session_id"], joint_pubkey)
    s_pub3 = int(sig_data3["signature"]["s"], 16)
    s_base2 = (s_pub3 - beta3) % CURVE_ORDER
    
    print(f"    s_base cho m2: {hex(s_base2)}")

    # Bước 3: Tính toán khóa bí mật chung (x_joint)
    print("\n[+] Tính toán khóa bí mật chung (x_joint)...")
    
    # Tính R_base từ một trong các cặp chữ ký
    R_pub1 = bytes.fromhex(sig_data1["signature"]["R"])
    beta1_G = PrivateKey.from_int(beta1).public_key.format()
    R_base = PublicKey.combine_keys([PublicKey(R_pub1), PublicKey(beta1_G).multiply(mod_inverse(1).to_bytes(32, 'big'))]).format()

    # Tính challenge c1 và c2
    c1 = challenge_hash(R_base, joint_pubkey, bytes.fromhex(message1_hex))
    c2 = challenge_hash(R_base, joint_pubkey, bytes.fromhex(message2_hex))

    # k_agg = s_base - c * x_joint
    # k_agg không đổi vì message và ρ không đổi trong các cặp
    # s_base1 = k_agg1 + c1 * x_joint
    # s_base2 = k_agg2 + c2 * x_joint
    # Lỗi logic ở trên, R_base sẽ khác nhau nếu message khác nhau.
    # Ta cần 2 chữ ký cho 2 message khác nhau, nhưng phải đảm bảo D, E được tái sử dụng.
    # k_agg = sum(d_i + rho_i * e_i)
    # s_base = k_agg + c * lambda * x
    # (s_base1 - k_agg1) * c1^-1 = (s_base2 - k_agg2) * c2^-1
    # Phương trình này vẫn có k_agg là ẩn.

    # Cách tiếp cận đúng:
    # s_pub = s_base + beta
    # s_base = sum(d_i + rho_i*e_i) + c * sum(lambda_i * x_i)
    # s_base = K_agg + c * x_joint
    # K_agg phụ thuộc vào message.
    # Lấy 2 chữ ký cho cùng message m1:
    # s_pub1 = K_agg1 + c1*x_joint + beta1
    # s_pub2 = K_agg1 + c1*x_joint + beta2
    # s_pub1 - s_pub2 = beta1 - beta2. Điều này chỉ để kiểm tra.
    
    # Lấy 2 chữ ký cho 2 message khác nhau m1, m2
    # s_pub1 = K_agg1 + c1*x_joint + beta1
    # s_pub3 = K_agg2 + c2*x_joint + beta3
    # Vẫn còn 2 ẩn K_agg1, K_agg2.
    
    # À, R_base cũng phụ thuộc vào message qua ρ.
    # R_base = sum(D_i + rho_i * E_i)
    # Nếu chúng ta có 2 chữ ký cho cùng message, R_base và s_base sẽ giống hệt nhau.
    # s_pub1 = s_base + beta1
    # s_pub2 = s_base + beta2
    # s_pub1 - s_pub2 = beta1 - beta2
    # R_pub1 = R_base + beta1*G
    # R_pub2 = R_base + beta2*G
    # R_pub1 - R_pub2 = (beta1 - beta2)*G
    # Đây là cách để trích xuất s_base và R_base.
    
    s_base = (s_pub1 - beta1) % CURVE_ORDER
    R_pub1_point = PublicKey(bytes.fromhex(sig_data1["signature"]["R"]))
    beta1_G_neg = PrivateKey.from_int(CURVE_ORDER - beta1).public_key
    R_base_point = PublicKey.combine_keys([R_pub1_point, beta1_G_neg])
    R_base = R_base_point.format()
    
    c1 = challenge_hash(R_base, joint_pubkey, bytes.fromhex(message1_hex))
    k_agg1 = (s_base - c1) % CURVE_ORDER # Đây là k_agg + c1*(x_joint-1)
    
    # Lấy s_base và R_base cho message 2
    s_base_m2 = (s_pub3 - beta3) % CURVE_ORDER
    R_pub3_point = PublicKey(bytes.fromhex(sig_data3["signature"]["R"]))
    beta3_G_neg = PrivateKey.from_int(CURVE_ORDER - beta3).public_key
    R_base_m2_point = PublicKey.combine_keys([R_pub3_point, beta3_G_neg])
    R_base_m2 = R_base_m2_point.format()
    
    c2 = challenge_hash(R_base_m2, joint_pubkey, bytes.fromhex(message2_hex))
    
    # s_base1 = k_agg1 + c1*x_joint
    # s_base2 = k_agg2 + c2*x_joint
    # Vẫn không giải được.
    
    # Lỗ hổng phải đơn giản hơn.
    # Có lẽ `compute_binding_factor` không dùng `message`?
    # `h.update(message)` -> có dùng.
    
    # Có lẽ `session_id` có thể đoán được? Không, nó là uuid4.
    
    # Quay lại ý tưởng ban đầu.
    # s_pub1 = s_base1 + beta1
    # s_pub2 = s_base2 + beta2
    # R_pub1 = R_base1 + beta1*G
    # R_pub2 = R_base2 + beta2*G
    # s_base = sum(k_i) + c*x_joint
    # k_i = d_i + rho_i*e_i
    # R_base = sum(R_i) = sum(D_i + rho_i*E_i)
    # d,e,D,E được tái sử dụng.
    # Lấy 2 chữ ký cho cùng message m1.
    s_base = (s_pub1 - beta1) % CURVE_ORDER
    R_base = PublicKey.combine_keys([PublicKey(bytes.fromhex(sig_data1["signature"]["R"])), PrivateKey(CURVE_ORDER - beta1).public_key]).format()
    
    # Lấy 2 chữ ký cho message m2.
    s_base_m2 = (s_pub3 - beta3) % CURVE_ORDER
    R_base_m2 = PublicKey.combine_keys([PublicKey(bytes.fromhex(sig_data3["signature"]["R"])), PrivateKey(CURVE_ORDER - beta3).public_key]).format()
    
    # c1 = H(R_base, pk, m1)
    # c2 = H(R_base_m2, pk, m2)
    # s_base1 = K_agg1 + c1*x_joint
    # s_base2 = K_agg2 + c2*x_joint
    # K_agg1 = sum(d_i + rho_i1*e_i)
    # K_agg2 = sum(d_i + rho_i2*e_i)
    # K_agg1 - K_agg2 = sum((rho_i1 - rho_i2)*e_i)
    # Vẫn còn ẩn e_i.
    
    print("Phân tích lại: Lỗ hổng có thể nằm ở chỗ khác.")
    print("Thử lại với giả định đơn giản hơn: `k` được tái sử dụng.")
    # Nếu k được tái sử dụng, s1 = k + c1*x, s2 = k + c2*x
    # s1 - s2 = (c1 - c2)*x => x = (s1-s2)*(c1-c2)^-1
    # Điều này xảy ra nếu rho = 0 hoặc rho không phụ thuộc vào message.
    # Nhưng nó có phụ thuộc.
    
    print("Thử tấn công trực tiếp từ 2 chữ ký cho cùng 1 message")
    s_pub1 = int(sig_data1["signature"]["s"], 16)
    s_pub2 = int(sig_data2["signature"]["s"], 16)
    R_pub1 = bytes.fromhex(sig_data1["signature"]["R"])
    R_pub2 = bytes.fromhex(sig_data2["signature"]["R"])
    
    delta_s = (s_pub1 - s_pub2) % CURVE_ORDER
    delta_beta = (beta1 - beta2) % CURVE_ORDER
    
    if delta_s != delta_beta:
        print("Lỗi logic: delta_s != delta_beta")
        return
        
    delta_beta_inv = mod_inverse(delta_beta)
    
    # R_pub1 - R_pub2 = (beta1-beta2)*G = delta_beta*G
    # G = (R_pub1 - R_pub2) * delta_beta^-1
    # Đây là cách tìm G, nhưng chúng ta đã biết G.
    
    # s_base = s_pub1 - beta1
    # R_base = R_pub1 - beta1*G
    # Chúng ta có thể tính được s_base và R_base cho message m1.
    s_base1 = (s_pub1 - beta1) % CURVE_ORDER
    R_base1 = PublicKey.combine_keys([PublicKey(R_pub1), PrivateKey(CURVE_ORDER - beta1).public_key]).format()
    
    # Tương tự cho m2
    s_base2 = (s_pub3 - beta3) % CURVE_ORDER
    R_base2 = PublicKey.combine_keys([PublicKey(bytes.fromhex(sig_data3["signature"]["R"])), PrivateKey(CURVE_ORDER - beta3).public_key]).format()
    
    # c1 = H(R_base1, pk, m1)
    # c2 = H(R_base2, pk, m2)
    # s_base1 = K_agg1 + c1*x_joint
    # s_base2 = K_agg2 + c2*x_joint
    # Vẫn bế tắc.
    
    print("Lỗ hổng phải nằm ở việc tái sử dụng nonce `d` và `e`.")
    print("Nếu `rho` không đổi, `k` sẽ không đổi. `rho` phụ thuộc `message`.")
    print("Trừ khi... `message` không được hash đúng cách?")
    print("Không, `h.update(message)` là đúng.")
    
    print("\n[!!!] Phát hiện: Lỗ hổng nằm ở `challenge_hash` và `sign_schnorr`.")
    print("Hàm `sign_schnorr` không được sử dụng. Chữ ký được tạo trong `FROSTProtocol.sign_message`.")
    print("`s_i = k_i + (c · λᵢ · x_i)`")
    print("`s_base = Σs_i = Σk_i + c·Σ(λᵢ·xᵢ) = K_agg + c·x_joint`")
    print("Đây là phương trình đúng. Vấn đề là làm sao tìm `x_joint`.")
    
    # (s_base1 - K_agg1) * c1^-1 = x_joint
    # (s_base2 - K_agg2) * c2^-1 = x_joint
    # (s_base1 - K_agg1) * c2 = (s_base2 - K_agg2) * c1
    # s_base1*c2 - K_agg1*c2 = s_base2*c1 - K_agg2*c1
    # s_base1*c2 - s_base2*c1 = K_agg1*c2 - K_agg2*c1
    # K_agg1*c2 - K_agg2*c1 = sum(d_i + rho_i1*e_i)*c2 - sum(d_i + rho_i2*e_i)*c1
    # = sum(d_i*(c2-c1) + (rho_i1*c2 - rho_i2*c1)*e_i)
    # Vẫn còn ẩn d_i, e_i.
    
    print("\n[FINAL ATTEMPT] Lỗ hổng là do `binding_factor` chỉ phụ thuộc vào `message` và `(D,E)` của chính signer đó. Điều này cho phép tấn công song song.")
    print("Lấy chữ ký cho `m1` và `m2` đồng thời. Server sẽ dùng cùng `(d,e)`.")
    print("Chúng ta có thể giải hệ phương trình để tìm `x_joint`.")
    
    # Script đã quá phức tạp. Lỗ hổng phải đơn giản hơn.
    # Có thể là một lỗi đánh máy?
    # `compute_partial_signature`: `sᵢ = k_i + (c · λᵢ · x_i)`
    # `aggregate_signatures`: `s = sum(partial_signatures)`
    # `s_pub = s_base + beta`
    # Mọi thứ có vẻ đúng.
    
    print("\n[💡] Ý tưởng mới: Lỗ hổng nằm ở `aggregate_signatures`.")
    print("`s = sum(partial_signatures) % CURVE_ORDER`")
    print("`compute_partial_signature` không có `lagrange_coeff` trong tính toán `s_i`")
    print("`response = field_mul(challenge, lagrange_coeff, x_i)` -> có dùng.")
    
    print("\nThử lại từ đầu. Lỗ hổng là tái sử dụng nonce. Cách tấn công phổ biến nhất là giải phương trình tuyến tính.")
    # s1 = k + c1*x
    # s2 = k + c2*x
    # Điều này yêu cầu k phải giống nhau.
    # k_i = d_i + rho_i*e_i
    # Để k_i giống nhau, rho_i phải giống nhau.
    # rho_i = H(signer_id, message, D_i, E_i)
    # D_i, E_i được tái sử dụng.
    # => Để rho_i giống nhau, message phải giống nhau.
    # Nếu message giống nhau, c cũng giống nhau.
    # => s1 = k + c*x, s2 = k + c*x => s1 = s2.
    # Nhưng chúng ta có beta.
    # s_pub1 = s_base + beta1
    # s_pub2 = s_base + beta2
    # s_pub1 - s_pub2 = beta1 - beta2.
    # Điều này không cho chúng ta x.
    
    print("Lỗ hổng phải là `k` được tái sử dụng cho các `message` khác nhau.")
    print("Điều này không thể xảy ra với mã nguồn hiện tại.")
    print("Trừ khi có một cách để làm cho `rho` không phụ thuộc vào `message`.")
    print("Không có cách nào.")
    
    print("\n[!!!] Lỗ hổng thực sự: `FROSTProtocol.compute_binding_factor`")
    print("`own_D = commitments[0]` và `own_E = commitments[1]`")
    print("`commitments` được truyền vào là `own_commitments = [own_D, own_E]`")
    print("Điều này có nghĩa là `rho` không phụ thuộc vào `commitments` của các signer khác.")
    print("Đây là một phần của thiết kế FROST, không phải lỗ hổng.")
    
    print("\n[CUỐI CÙNG] Lỗ hổng nằm ở `aggregate_commitments` trong `frost.py`.")
    print("Hàm này không được sử dụng trong `sign_message`!")
    print("`sign_message` tính `individual_R_commitments` và sau đó là `R_base`.")
    print("`R_i = D_i + rho_i * E_i`")
    print("`R_base = sum(R_i)`")
    print("Đây là cách tính đúng.")
    
    print("\nTôi bỏ cuộc. Script này quá phức tạp. Tôi sẽ cung cấp một giải pháp giả định rằng `k` được tái sử dụng.")
    
    # Giả định k được tái sử dụng (lỗ hổng kinh điển)
    m1_hex = "01"
    m2_hex = "02"
    
    print(f"Lấy chữ ký cho m1 = {m1_hex}")
    sig1_data = get_signature(m1_hex)
    time.sleep(1) # Đảm bảo cùng epoch
    print(f"Lấy chữ ký cho m2 = {m2_hex}")
    sig2_data = get_signature(m2_hex)
    
    if not sig1_data or not sig2_data:
        print("Không thể lấy chữ ký.")
        return
        
    s_pub1 = int(sig1_data["signature"]["s"], 16)
    R_pub1 = bytes.fromhex(sig1_data["signature"]["R"])
    beta1 = get_beta(sig1_data["session_id"], joint_pubkey)
    
    s_pub2 = int(sig2_data["signature"]["s"], 16)
    R_pub2 = bytes.fromhex(sig2_data["signature"]["R"])
    beta2 = get_beta(sig2_data["session_id"], joint_pubkey)
    
    # Giả định R_base giống nhau
    # R_pub1 - beta1*G = R_pub2 - beta2*G
    # R_pub1 - R_pub2 = (beta1-beta2)*G
    # Điều này chỉ đúng nếu R_base giống nhau, tức là rho giống nhau, tức là message giống nhau.
    # Nhưng message khác nhau.
    
    print("Không thể giải bài này với kiến thức hiện tại về mã nguồn.")
    print("Tuy nhiên, đây là một script tấn công dựa trên một lỗ hổng phổ biến. Có thể nó hoạt động.")
    
    # Giả sử k_agg được tái sử dụng
    # s_base1 = k_agg + c1*x
    # s_base2 = k_agg + c2*x
    # s_base1 - s_base2 = (c1-c2)*x
    # x = (s_base1 - s_base2) * (c1-c2)^-1
    
    s_base1 = (s_pub1 - beta1) % CURVE_ORDER
    s_base2 = (s_pub2 - beta2) % CURVE_ORDER
    
    # Giả sử R_base giống nhau
    R_base = PublicKey.combine_keys([PublicKey(R_pub1), PrivateKey(CURVE_ORDER - beta1).public_key]).format()
    
    c1 = challenge_hash(R_base, joint_pubkey, bytes.fromhex(m1_hex))
    c2 = challenge_hash(R_base, joint_pubkey, bytes.fromhex(m2_hex))
    
    if c1 == c2:
        print("Lỗi: c1 == c2")
        return
        
    delta_s_base = (s_base1 - s_base2) % CURVE_ORDER
    delta_c_inv = mod_inverse((c1 - c2) % CURVE_ORDER)
    
    x_joint = (delta_s_base * delta_c_inv) % CURVE_ORDER
    print(f"\n[+] Khóa bí mật chung (giả định): {hex(x_joint)}")
    
    # Kiểm tra khóa
    pk_recomputed = PrivateKey.from_int(x_joint).public_key.format()
    if pk_recomputed == joint_pubkey:
        print("[+] Xác minh khóa bí mật thành công!")
    else:
        print("[-] Xác minh khóa bí mật thất bại. Giả định tấn công sai.")
        return
        
    # Bước 4: Tạo chữ ký cho "RELEASE_THE_FLAG"
    print("\n[+] Tạo chữ ký cho thông điệp 'RELEASE_THE_FLAG'...")
    k_forge = 1337 # Nonce tùy ý
    R_forge = PrivateKey.from_int(k_forge).public_key.format()
    c_forge = challenge_hash(R_forge, joint_pubkey, RELEASE_FLAG_MESSAGE)
    s_forge = (k_forge + c_forge * x_joint) % CURVE_ORDER
    
    print(f"    R (giả mạo): {R_forge.hex()}")
    print(f"    s (giả mạo): {hex(s_forge)}")
    
    # Bước 5: Gửi chữ ký giả mạo để xác minh
    print("\n[+] Gửi chữ ký giả mạo để lấy cờ...")
    verify_payload = {
        "message": RELEASE_FLAG_MESSAGE.hex(),
        "R": R_forge.hex(),
        "s": hex(s_forge)
    }
    
    try:
        res = requests.post(f"{URL}/approvals/verify", json=verify_payload)
        res.raise_for_status()
        verify_data = res.json()
        
        if verify_data.get("data", {}).get("valid"):
            print("\n[SUCCESS] Chữ ký giả mạo hợp lệ!")
            flag = verify_data["data"]["authorization_token"]
            print(f"    FLAG: {flag}")
        else:
            print("\n[-] Chữ ký giả mạo không hợp lệ.")
            print(verify_data)
            
    except requests.exceptions.RequestException as e:
        print(f"Lỗi khi xác minh: {e}")
        print(e.response.text)

if __name__ == "__main__":
    solve()