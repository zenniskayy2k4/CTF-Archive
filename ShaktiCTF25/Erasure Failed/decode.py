import base64
from Crypto.Util.number import long_to_bytes
import gmpy2

# Bước 1: Trích xuất và giải mã dữ liệu Base64 từ file PEM
b64_data = (
    "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"
)
der_fragment = base64.b64decode(b64_data)

# Hàm trợ giúp để phân tích một số nguyên từ dữ liệu DER
def parse_der_integer(data, offset):
    if data[offset] != 0x02:
        raise ValueError("Invalid DER Integer tag")
    offset += 1
    
    len_byte = data[offset]
    offset += 1
    if len_byte & 0x80:
        len_len = len_byte & 0x7F
        length = int.from_bytes(data[offset:offset+len_len], 'big')
        offset += len_len
    else:
        length = len_byte
    
    value = int.from_bytes(data[offset:offset+length], 'big')
    offset += length
    
    return value, offset

# Bước 2: Tìm e và phân tích d, p
e = 65537
e_der = b'\x02\x03\x01\x00\x01'
e_offset = der_fragment.find(e_der)

if e_offset == -1:
    print("Lỗi: Không tìm thấy e = 65537 trong dữ liệu DER.")
    exit()

print(f"Tìm thấy e tại vị trí: {e_offset}")
d_start_offset = e_offset + len(e_der)

d, p_start_offset = parse_der_integer(der_fragment, d_start_offset)
print("Đã khôi phục thành công d (số mũ bí mật).")

p, q_start_offset = parse_der_integer(der_fragment, p_start_offset)
print("Đã khôi phục thành công p (số nguyên tố 1).")

# Bước 3: Khôi phục q
k_mul_phi = e * d - 1
print("Đang tìm kiếm q...")
q = 0
for k in range(1, e):
    if (k_mul_phi % k == 0):
        phi_candidate = k_mul_phi // k
        if (phi_candidate % (p - 1) == 0):
            q_minus_1 = phi_candidate // (p - 1)
            q_candidate = q_minus_1 + 1
            
            if q_candidate.bit_length() == 2048 and gmpy2.is_prime(q_candidate):
                q = q_candidate
                print(f"Đã tìm thấy q với k = {k}!")
                break
if q == 0:
    print("Lỗi: Không thể khôi phục q.")
    exit()

# Bước 4: Giải mã
with open("ciphertext.txt", "r") as f:
    ct = int(f.read())

n = p * q
m = pow(ct, d, n)
flag = long_to_bytes(m)

print("\n-------------------")
print("FLAG:", flag.decode())
print("-------------------")