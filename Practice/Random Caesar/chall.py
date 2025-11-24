# usr/bin/env python3
import random
from secret import FLAG

ALPHABET = ''.join([chr(i) for i in range(32, 127)])
ALPHABET_LEN = len(ALPHABET)

def generate_key(length):
    key = []
    for _ in range(length):
        key.append((random.randint(1, 26), random.choice([-1, 1])))
    return key

def encrypt(plaintext, key):
    ciphertext = ""
    for i, char in enumerate(plaintext):
        if char not in ALPHABET:
            ciphertext += char
            continue
        shift, direction = key[i]
        char_index = ALPHABET.find(char)
        new_index = (char_index + shift * direction) % ALPHABET_LEN
        ciphertext += ALPHABET[new_index]
        
    return ciphertext

random.seed(1337) # Fixed seed for reproducibility

KNOWN_PLAINTEXT = "This is a simple cryptographic challenge to test the Caesar cipher with random keys." # This is a present

key_length = max(len(KNOWN_PLAINTEXT), len(FLAG))
key_stream = generate_key(key_length)

encrypted_known_text = encrypt(KNOWN_PLAINTEXT, key_stream[:len(KNOWN_PLAINTEXT)])
encrypted_flag = encrypt(FLAG, key_stream[:len(FLAG)])

with open("output.txt", "w", encoding="utf-8") as f:
    f.write(f"Encrypted Test Message: {encrypted_known_text}\n")
    f.write(f"Encrypted Flag: {encrypted_flag}")