hex_str = "5958051a1b170013520746265a0e51435b36165752470b7f03591d1b364b501608616e"
key = "i could be something to this"

def xor_decrypt(hex_input, key_input):
    ciphertext = bytes.fromhex(hex_input)
    decrypted = ""
    for i in range(len(ciphertext)):
        # XOR từng byte của hex với từng byte của key (lặp lại key nếu cần)
        decrypted += chr(ciphertext[i] ^ ord(key_input[i % len(key_input)]))
    return decrypted

print("Flag:", xor_decrypt(hex_str, key))