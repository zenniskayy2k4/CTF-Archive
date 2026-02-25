from pwn import *
from Crypto.Util.number import bytes_to_long, long_to_bytes, inverse
from hashlib import sha256
import re

# ==========================================
# CẤU HÌNH
# ==========================================
context.log_level = 'info'
HOST = 'challenge.cnsc.com.vn' 
PORT = 31364

BASE85_ALPHABET = b"!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstu"
B85_MAP = {c: i for i, c in enumerate(BASE85_ALPHABET)}

# Tạo list số nguyên tố nhỏ nội bộ (chỉ cần đến 5000 là đủ nhanh và hiệu quả)
def get_small_primes(n):
    sieve = [True] * n
    for i in range(3, int(n**0.5) + 1, 2):
        if sieve[i]:
            sieve[i*i::2*i] = [False] * ((n - i*i - 1) // (2*i) + 1)
    return [2] + [i for i in range(3, n, 2) if sieve[i]]

# Chỉ cần lọc đến 5000, Python xử lý cái này trong tích tắc
SMALL_PRIMES = get_small_primes(5000)

def decode_b85_output(s):
    try:
        out = b""
        for i in range(0, len(s), 5):
            chunk_s = s[i:i+5]
            if len(chunk_s) < 5: break
            val = 0
            for c in chunk_s:
                val = val * 85 + B85_MAP[c]
            out += long_to_bytes(val, 4)
        return out
    except:
        return b""

def encode_b85_input(data):
    out = b""
    for i in range(0, len(data), 4):
        chunk_val = bytes_to_long(data[i:i+4])
        chars = []
        for _ in range(5):
            chars.append(BASE85_ALPHABET[chunk_val % 85])
            chunk_val //= 85
        out += bytes(chars[::-1])
    return out

def solve():
    while True:
        r = None
        try:
            # Kết nối
            r = remote(HOST, PORT)
            
            # 1. Nhận N
            r.recvuntil(b"N = ")
            n_b85 = r.recvline().strip()
            N_bytes = decode_b85_output(n_b85)
            
            if len(N_bytes) != 384:
                r.close()
                continue
                
            N = bytes_to_long(N_bytes)
            
            # 2. Tìm N' (Siêu tốc)
            found = False
            prime_N = 0
            magic_char = 0
            
            n_mutable = bytearray(N_bytes)
            
            # Thử 85 trường hợp
            for char_code in BASE85_ALPHABET:
                n_mutable[0] = char_code
                candidate_N = bytes_to_long(n_mutable)
                
                # BƯỚC 1: Lọc bằng phép chia (Rất nhanh với list nhỏ)
                is_composite = False
                for p in SMALL_PRIMES:
                    if candidate_N % p == 0:
                        is_composite = True
                        break
                if is_composite: continue 

                # BƯỚC 2: Fermat Test (Chốt hạ)
                # Chỉ chạy bước này với số lượng rất ít ứng viên lọt qua bước 1
                if pow(2, candidate_N - 1, candidate_N) == 1:
                    log.success(f"FOUND PRIME N'! Char: {chr(char_code)}")
                    prime_N = candidate_N
                    magic_char = char_code
                    found = True
                    break
            
            if not found:
                r.close()
                continue
            
            # 3. Tính toán Exploit
            target_msg = b"1_d4r3_y0u_70_519n_7h15_3x4c7_51x7y_f0ur_by73_57r1n9_w17h_my_k3y"
            h_target = bytes_to_long(sha256(target_msg).digest())
            e = 0x10001
            
            d_prime = inverse(e, prime_N - 1)
            sig_forge = pow(h_target, d_prime, prime_N)
            sig_bytes = long_to_bytes(sig_forge, 384)
            sig_payload = encode_b85_input(sig_bytes)
            
            payload_overflow = b'!' * 79 + bytes([magic_char])

            # 4. Gửi Exploit (Xử lý kỹ phần nhận phản hồi để không bị de-sync)
            
            # --- Giai đoạn 1: Gửi Payload làm hỏng N ---
            r.sendlineafter(b"Verify(1): ", b"0")
            r.recvuntil(b"base85:\n")
            r.sendline(payload_overflow)
            
            # QUAN TRỌNG: Sau khi gửi payload ở option 0, server sẽ in ra "sig = ..."
            # Ta phải đọc bỏ dòng này để đồng bộ lại luồng nhập xuất
            r.recvuntil(b"sig = ")
            r.recvline() 
            
            # --- Giai đoạn 2: Gửi chữ ký giả ---
            r.sendlineafter(b"Verify(1): ", b"1")
            r.recvuntil(b"base85:\n")
            r.sendline(sig_payload)
            
            # 5. Nhận Flag
            response = r.recvall(timeout=5)
            
            if b"W1{" in response:
                print("\n" + "="*40)
                try:
                    flag = re.search(b"W1{.*}", response).group().decode()
                    print(f"FLAG: {flag}")
                except:
                    print(response)
                print("="*40 + "\n")
                break
            else:
                log.info("Failed verify. Retry.")
                r.close()

        except KeyboardInterrupt:
            break
        except Exception:
            if r: r.close()

if __name__ == "__main__":
    solve()