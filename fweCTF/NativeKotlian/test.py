def decrypt_file(encrypted_file, output_file, key_str):
    """
    Emulates the exact decryption logic found in the Ghidra pseudo-code.
    The operation is: plaintext_byte = (ciphertext_byte + key_byte) % 256.
    """
    key = key_str.encode('ascii')
    key_len = len(key)
    
    try:
        with open(encrypted_file, 'rb') as f_in:
            ciphertext = f_in.read()
    except FileNotFoundError:
        print(f"Error: File '{encrypted_file}' not found.")
        return

    plaintext = bytearray()
    for i, encrypted_byte in enumerate(ciphertext):
        key_byte = key[i % key_len]
        
        # === MÔ PHỎNG CHÍNH XÁC PHÉP TOÁN TỪ GHIDRA ===
        decrypted_byte = (encrypted_byte + key_byte) % 256
        plaintext.append(decrypted_byte)

    with open(output_file, 'wb') as f_out:
        f_out.write(plaintext)
        
    print(f"File decrypted successfully to '{output_file}'!")

if __name__ == "__main__":
    encrypted_file_name = 'W3e11yC7.tar.gz.encrypted'
    decrypted_file_name = 'W3e11yC7.tar.gz'
    
    # The real key based on the author's hint
    key_string = "strings!"
    
    decrypt_file(encrypted_file_name, decrypted_file_name, key_string)