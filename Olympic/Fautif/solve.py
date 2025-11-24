import string

hex_encoded_flag = "59544c5065417167414774786762784c7a63646b6874417b76724178417a6b787f66724c7d7576747672794c7769687e794c7b7b75667b6b687b6d747878737f7970794c64717b6a667e797a4176644c6d756f7d6f70744c757f794c7c6169797863674c647c647d797a737d3f6e14"
encrypted_bytes = bytes.fromhex(hex_encoded_flag)

print("Brute-forcing 65536 XOR keys, tìm kiếm chuỗi có ý nghĩa...")

# Các ký tự hợp lệ trong một chuỗi đã mã hóa Enigma (chữ cái và ký tự đặc biệt)
plausible_chars = string.ascii_letters + string.digits + "{}_-!"

for k1 in range(256):
    for k2 in range(256):
        key = [k1, k2]
        decrypted = bytearray()
        
        for i in range(len(encrypted_bytes)):
            decrypted.append(encrypted_bytes[i] ^ key[i % 2])

        try:
            decoded_string = decrypted.decode('ascii')
            # Kiểm tra xem chuỗi có "hợp lý" không: phần lớn là các ký tự in được
            plausible_count = sum(1 for char in decoded_string if char in plausible_chars)
            
            # Nếu hơn 90% ký tự là hợp lệ, đó là một ứng cử viên sáng giá
            if plausible_count / len(decoded_string) > 0.9:
                # Và nếu nó bắt đầu bằng một chữ cái (rất có khả năng)
                if 'a' <= decoded_string[0].lower() <= 'z':
                    print(f"\n[+] Tìm thấy key khả thi: 0x{k1:02x}, 0x{k2:02x}")
                    print(f"[+] Chuỗi đã giải mã Enigma: {decoded_string}")

        except (UnicodeDecodeError, IndexError):
            continue

print("\nBrute-force hoàn tất.")