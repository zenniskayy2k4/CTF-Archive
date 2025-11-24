def decrypt_file(encrypted_file, output_file, key_str):
    """
    Decrypts the file using a repeating key additive cipher.
    The operation is: plaintext_byte = (encrypted_byte - key_byte) % 256.
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
        # Phép toán ngược lại của phép cộng
        decrypted_byte = (encrypted_byte - key_byte + 256) % 256
        plaintext.append(decrypted_byte)

    with open(output_file, 'wb') as f_out:
        f_out.write(plaintext)
        
    print(f"Successfully decrypted '{encrypted_file}' to '{output_file}' with the correct key!")

if __name__ == "__main__":
    encrypted_file_name = 'W3e11yC7.tar.gz.encrypted'
    decrypted_file_name = 'W3e11yC7.tar.gz'
    
    # Khóa rất có thể là đây, dựa vào gợi ý của tác giả
    key_string = "strings!"
    
    decrypt_file(encrypted_file_name, decrypted_file_name, key_string)