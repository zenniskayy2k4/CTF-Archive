from Crypto.Cipher import DES
import re

def main():
    print("--- Local Decryption & Analysis Script ---")
    try:
        with open("key2.bin", "rb") as f: key2 = f.read()
        with open("encrypted_flag.bin", "rb") as f: encrypted_flag_raw = f.read()
    except FileNotFoundError as e:
        print(f"Error: Could not find required file: {e.filename}"); return

    print(f"Loaded KEY2: {key2.hex()}")
    print(f"Loaded raw encrypted data (len={len(encrypted_flag_raw)} bytes): {encrypted_flag_raw.hex()}")

    encrypted_flag = encrypted_flag_raw
    if len(encrypted_flag) % 8 != 0:
        padding = 8 - (len(encrypted_flag) % 8)
        encrypted_flag += b'\x00' * padding
        print(f"Padded data to {len(encrypted_flag)} bytes.")
    
    try:
        cipher2 = DES.new(key2, DES.MODE_ECB)
        decrypted_data = cipher2.decrypt(encrypted_flag)
        
        # Cắt bỏ phần dữ liệu rác do padding gây ra
        original_len = len(encrypted_flag_raw)
        decrypted_data_unpadded = decrypted_data[:original_len]

        print("\n--- DECRYPTED DATA (unpadded) ---")
        print(f"HEX: {decrypted_data_unpadded.hex()}")
        print(f"ASCII (repr): {repr(decrypted_data_unpadded)}")
        
        match = re.search(b'csawctf\\{.*?}', decrypted_data)
        if match:
            flag = match.group(0)
            print("\n--- FLAG FOUND ---")
            print(f"FLAG: {flag.decode('utf-8', 'ignore')}")
        else:
            print("\n--- Flag pattern not found automatically. Please inspect manually. ---")

    except Exception as e:
        print(f"\nAn error occurred during decryption: {e}")

if __name__ == "__main__":
    main()