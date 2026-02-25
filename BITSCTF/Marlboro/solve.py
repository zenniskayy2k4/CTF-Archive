# solve.py
key_hex = "c7027f5fdeb20dc7308ad4a6999a8a3e069cb5c8111d56904641cd344593b657"
key = bytes.fromhex(key_hex)

with open("encrypted.bin", "rb") as f:
    encrypted_data = f.read()

# Thực hiện phép XOR xoay vòng (cycling XOR)
decrypted_data = bytes([encrypted_data[i] ^ key[i % len(key)] for i in range(len(encrypted_data))])

with open("source.mal", "wb") as f:
    f.write(decrypted_data)

print("Đã giải mã xong! File đầu ra: source.mal")