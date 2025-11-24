input_file = "encrypted.bin"
output_file = "challenge.elf"
key = 0x67

try:
    with open(input_file, "rb") as f:
        data = f.read()

    # XOR giải mã
    decrypted = bytearray([b ^ key for b in data])

    with open(output_file, "wb") as f:
        f.write(decrypted)
    
    print(f"[-] Đã giải mã xong! File đầu ra: {output_file}")
    
    # Kiểm tra nhanh xem có đúng header ELF không
    if decrypted[:4] == b'\x7fELF':
        print("[-] Xác nhận đây là file thực thi Linux (ELF).")
    else:
        print("[!] Cảnh báo: Header không giống file ELF, có thể sai Key hoặc sai cách export.")

except FileNotFoundError:
    print("Không tìm thấy file input. Hãy chắc chắn bạn đã export từ Wireshark đúng tên.")