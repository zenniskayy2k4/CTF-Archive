import binascii

# Dữ liệu đề bài
hex_cipher = "6032746a643360617865696569606e6c725962686562616657636e6360676359767368607665707c696f667d606b685967726d5b65775749484e5d4d79"

key = "IIITDIIITDIIITD"

# --- Phần code giải mã ---
cipher_bytes = binascii.unhexlify(hex_cipher)
key_bytes = key.encode('utf-8')
plaintext_bytes = bytearray()

for i in range(len(cipher_bytes)):
    plain_byte = cipher_bytes[i] ^ key_bytes[i % len(key_bytes)]
    plaintext_bytes.append(plain_byte)

# In kết quả cuối cùng
print(f"Đang giải mã với key: '{key}'")
print("Kết quả:")
print(plaintext_bytes.decode())