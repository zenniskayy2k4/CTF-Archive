from Crypto.Util.number import long_to_bytes

p  = 14912432766367177751
g  = 2784687438861268863
h  = 8201777436716393968
c1 = 12279519522290406516
c2 = 10734305369677133991

# Bước 1: Khóa bí mật x đã tìm được từ SageMath
x = 276108400367396891

# Bước 2: Tính shared secret s = c1^x mod p
s = pow(c1, x, p)

# Bước 3: Tính nghịch đảo modular của s (s^-1 mod p)
s_inv = pow(s, -1, p)

# Bước 4: Khôi phục bản rõ m dưới dạng số
# m = c2 * s_inv mod p
m = (c2 * s_inv) % p

print(f"Giá trị số của m: {m}")

# Bước 5: Chuyển số m thành chuỗi ký tự (bytes to string)
message_bytes = long_to_bytes(m)
plaintext = message_bytes.decode('utf-8')

print(f"Bản rõ đã khôi phục: {plaintext}")

# Định dạng flag theo yêu cầu
flag = f"brunner{{{plaintext}}}"
print(f"Flag: {flag}")