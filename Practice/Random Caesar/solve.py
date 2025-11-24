# usr/bin/env python3
ALPHABET = ''.join([chr(i) for i in range(32, 127)])
ALPHABET_LEN = len(ALPHABET)

ENCRYPTED_KNOWN_TEXT = r"""hU#!*R-$v#!$Wd]k6wXg[wZQ]ZfwjUm|aPS%|oy}v]mt{wq#k#Pg,@mNlq'2]!c#k'}e~~"s|t$iV`p`n+n?"""
ENCRYPTED_FLAG = r"""mb-n~X\X[~P{OgRxuxy\N6Ja{m^ns&\})\F$JzqIjHl%{qqBRAh"""

KNOWN_PLAINTEXT = "This is a simple cryptographic challenge to test the Caesar cipher with random keys."

def recover_key(plaintext, ciphertext):
    """Khôi phục lại key (chuỗi các net_shift) từ plaintext và ciphertext."""
    recovered_key = []
    for i, p_char in enumerate(plaintext):
        # Theo code gốc, ký tự không có trong ALPHABET sẽ được bỏ qua
        # Nhưng code của bạn mã hóa tất cả ký tự in được, nên không cần check.
        c_char = ciphertext[i]
        
        p_index = ALPHABET.find(p_char)
        c_index = ALPHABET.find(c_char)
        
        # net_shift = (c_index - p_index) % ALPHABET_LEN
        net_shift = (c_index - p_index + ALPHABET_LEN) % ALPHABET_LEN
        
        recovered_key.append(net_shift)
        
    return recovered_key

def decrypt(ciphertext, key):
    """Giải mã ciphertext bằng key đã khôi phục."""
    plaintext = ""
    for i, c_char in enumerate(ciphertext):
        net_shift = key[i]
        c_index = ALPHABET.find(c_char)
        
        # p_index = (c_index - net_shift) % ALPHABET_LEN
        p_index = (c_index - net_shift + ALPHABET_LEN) % ALPHABET_LEN

        plaintext += ALPHABET[p_index]
        
    return plaintext

# Bước 1: Khôi phục lại key từ tin nhắn thử nghiệm
key_stream = recover_key(KNOWN_PLAINTEXT, ENCRYPTED_KNOWN_TEXT)
print(f"[*] Recovered key stream (first 10 elements): {key_stream[:10]}")
print(f"[*] Length of recovered key: {len(key_stream)}")

# Bước 2: Dùng key đã khôi phục để giải mã flag
decrypted_flag = decrypt(ENCRYPTED_FLAG, key_stream)

print("\n[+] Decrypted Flag:")
print(decrypted_flag)