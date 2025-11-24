import itertools

def xor(x, y):
    return bytes([a ^ b for a, b in zip(x, y)])

with open('flag-enc.bmp', 'rb') as f:
    enc = f.read()

# Tách header và data
header_len = len(enc) - 1024 ** 2 * 3
header = enc[:header_len]
data = enc[header_len:]

# Giả sử vùng nền là màu xám (RGB: 128,128,128)
gray_pixel = b'\x80\x80\x80'

# Tìm key stream bằng cách XOR với màu xám
chunked = list(itertools.zip_longest(*[iter(data)] * 3, fillvalue=0))
keystream = [xor(chunk, gray_pixel) for chunk in chunked]

# Giải mã ảnh (giả sử toàn bộ ảnh là màu xám)
decrypted = [xor(chunk, ks) for chunk, ks in zip(chunked, keystream)]

with open('flag-dec.bmp', 'wb') as f:
    f.write(header)
    f.write(b''.join(decrypted))
print("Đã giải xong, kiểm tra file flag-dec.bmp")