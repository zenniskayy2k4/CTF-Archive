import hashlib
from Crypto.Cipher import AES
import os

ASSETS_FILENAME = "assets.bin"

def solve():
    if not os.path.exists(ASSETS_FILENAME):
        print(f"[!] Error: '{ASSETS_FILENAME}' not found.")
        return

    try:
        with open(ASSETS_FILENAME, "rb") as f:
            print(f"[*] Reading data from '{ASSETS_FILENAME}'...")

            f.read(8) # Bỏ qua Header

            fingerprint_from_file_be = f.read(96)
            if len(fingerprint_from_file_be) != 96:
                print("[!] Error: Could not read the full 96-byte fingerprint.")
                return

            nonce = f.read(12)
            encrypted_data_with_tag = f.read()
            tag = encrypted_data_with_tag[-16:]
            ciphertext = encrypted_data_with_tag[:-16]

            print(f"  - Nonce: {nonce.hex()}")
            print(f"  - Ciphertext length: {len(ciphertext)} bytes")
            print(f"  - Auth Tag: {tag.hex()}")
            
            print("\n[*] Reconstructing the exact memory buffer for SHA256...")

            # --- SỬA LỖI CUỐI CÙNG: ĐẢO NGƯỢC BYTE TRONG TỪNG KHỐI 8-BYTE ---
            
            correct_buffer_for_sha256 = bytearray()
            # Lặp qua 96 byte theo từng khối 8-byte
            for i in range(0, len(fingerprint_from_file_be), 8):
                # Lấy ra một khối 8-byte (một giá trị 64-bit Big-Endian)
                word_be = fingerprint_from_file_be[i : i+8]
                
                # Đảo ngược thứ tự byte trong khối đó để mô phỏng cách lưu trữ Little-Endian
                word_le = word_be[::-1]
                
                # Nối vào buffer cuối cùng
                correct_buffer_for_sha256.extend(word_le)
            
            print(f"  - Successfully created little-endian memory representation.")

            # Tính SHA256 của buffer đã được chuyển đổi chính xác
            aes_key = hashlib.sha256(correct_buffer_for_sha256).digest()
            print(f"  - Generated final AES-256 Key: {aes_key.hex()}")

            # --- Bắt đầu giải mã ---
            print("\n[*] Decrypting flag using AES-GCM...")

            cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
            
            decrypted_flag_bytes = cipher.decrypt_and_verify(ciphertext, tag)
            
            flag = decrypted_flag_bytes.decode('utf-8')
            
            print("\n" + "="*50)
            print(f"[SUCCESS] Flag found!")
            print(f"FLAG: {flag}")
            print("="*50)

    except (ValueError, KeyError) as e:
        print("\n[!] FAILED! Decryption error: MAC check failed.")
    except Exception as e:
        print(f"[!] An unexpected error occurred: {e}")

if __name__ == "__main__":
    solve()