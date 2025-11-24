from Crypto.Cipher import ARC4
import binascii

def solve():
    # --- Dữ liệu đã được xác minh ---
    base_key = bytearray(binascii.unhexlify("3b3a3a243d32243b3f33243b38390a00"))
    
    # Ciphertext chính xác từ payload của gói tin 29 (dữ liệu mã hóa RC4)
    ciphertext_hex = (
        "d00a0a0a0a0a0a0a0b0a0a0a0a0a0a0a"
        "0b0a0a0a0a0a0a0a5c0a0a0a0a0a0a0a"
        "da420a0a0a0a0a0a2a0a0a0a0a0a0a0a"
        "070a0a0a0e0a0a0a020a0a0a0a0a0a0a"
        "120a0a0a0a0a0a0a540a0a0a090a0a0a"
        "fa430a0a0a0a0a0a7a0a0a0a0a0a0a0a"
        "0b0a0a0a0a0a0a0a620a0a0a0a0a0a0a"
        "6a400a0a0a0a0a0a890a0a0a0a0a0a0a"
        + "0a" * (232 - 128)
    )
    ciphertext = binascii.unhexlify(ciphertext_hex)

    print("Bắt đầu brute-force khóa RC4...")

    # Vòng lặp Brute-force số nguyên đầu vào i (0-255)
    for i in range(256):
        print(f"Đang thử số nguyên: {i}...", end='\r')
        
        # Tạo key tạm thời cho mỗi lần lặp
        temp_key = base_key[:] # Tạo một bản sao để thay đổi
        
        # --- Mô phỏng logic tạo khóa phức tạp từ decompiler ---
        
        # Phần 1: XOR 12 byte đầu với dword được tạo bằng cách lặp lại byte i
        xor_dword_val = bytes([i, i, i, i])
        for j in range(0, 12, 4):
            chunk = temp_key[j:j+4]
            xored_chunk = bytes([a ^ b for a, b in zip(chunk, xor_dword_val)])
            temp_key[j:j+4] = xored_chunk

        # Phần 2: XOR 3 byte tiếp theo (index 12, 13, 14) với byte i gốc
        for j in range(12, 15):
            temp_key[j] ^= i
            
        # Byte 15 không đổi.
        final_rc4_key = bytes(temp_key)

        try:
            # Sử dụng ARC4 (RC4) để giải mã
            cipher = ARC4.new(final_rc4_key)
            decrypted_data = cipher.decrypt(ciphertext)
            
            # Kiểm tra với format flag chính xác
            if decrypted_data.startswith(b'CSCV2025{'):
                print(f"\n\n[+] TÌM THẤY FLAG!")
                print(f"[+] Số nguyên đầu vào đúng: {i}")
                print(f"[+] Khóa RC4: {final_rc4_key.hex()}")
                
                flag = decrypted_data.split(b'}')[0].decode('ascii') + '}'
                print(f"\n[+] FLAG: {flag}")
                return
        except Exception:
            continue
            
    print("\n\n[-] Không tìm thấy flag.")

if __name__ == "__main__":
    solve()
    print("\nHoàn tất.")