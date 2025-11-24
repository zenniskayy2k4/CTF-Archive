import base64
import string

def try_all_methods():
    encoded = "lHU0aIG6Rj9kfkm2TY5yb29qzHOaJ29tO2PzuDKlO2XwvMClflNpSF5kYRBnF0ifY0OaHNopBkuJSwpuaFwepVCHVeFhdWLoJ3BkcG1xbALjaZ5l=="
    
    print("=== Method 1: Caesar shift on base64 alphabet ===")
    b64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    
    def shift_base64(s, shift):
        shifted = ""
        for c in s:
            if c in b64_chars:
                idx = (b64_chars.index(c) + shift) % 64
                shifted += b64_chars[idx]
            else:
                shifted += c
        return shifted
    
    for i in range(1, 64):  # Skip 0 as it's the original
        try:
            shifted = shift_base64(encoded, i)
            decoded = base64.b64decode(shifted)
            result = decoded.decode('utf-8', errors='ignore')
            if '07CTF{' in result:
                print(f"FOUND with shift {i}: {result}")
                return result
            elif 'CTF' in result or result.isprintable():
                print(f"Shift {i}: {result}")
        except Exception as e:
            continue
    
    print("\n=== Method 2: ROT13/ROT variations on the string ===")
    def rot_n(text, n):
        result = ""
        for char in text:
            if char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                result += chr((ord(char) - base + n) % 26 + base)
            else:
                result += char
        return result
    
    for n in range(1, 26):
        try:
            rotated = rot_n(encoded, n)
            decoded = base64.b64decode(rotated)
            result = decoded.decode('utf-8', errors='ignore')
            if '07CTF{' in result:
                print(f"FOUND with ROT{n}: {result}")
                return result
        except:
            continue
    
    print("\n=== Method 3: XOR with single byte ===")
    try:
        original_decoded = base64.b64decode(encoded)
        for key in range(1, 256):
            xored = bytes([b ^ key for b in original_decoded])
            result = xored.decode('utf-8', errors='ignore')
            if '07CTF{' in result:
                print(f"FOUND with XOR key {key}: {result}")
                return result
    except:
        pass
    
    print("\n=== Method 4: Reverse then decode ===")
    try:
        reversed_encoded = encoded[::-1]
        decoded = base64.b64decode(reversed_encoded)
        result = decoded.decode('utf-8', errors='ignore')
        if '07CTF{' in result:
            print(f"FOUND with reverse: {result}")
            return result
    except:
        pass
    
    print("\n=== Method 5: Custom base64 alphabet (ladybug themed) ===")
    # Try different custom alphabets
    custom_alphabets = [
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",  # standard
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/",  # lowercase first
        "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/",  # numbers first
    ]
    
    standard_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    
    for i, custom_alphabet in enumerate(custom_alphabets[1:], 1):  # Skip standard
        try:
            # Create translation table
            translation = str.maketrans(standard_alphabet, custom_alphabet)
            translated = encoded.translate(translation)
            decoded = base64.b64decode(translated)
            result = decoded.decode('utf-8', errors='ignore')
            if '07CTF{' in result:
                print(f"FOUND with custom alphabet {i}: {result}")
                return result
        except:
            continue
    
    print("\n=== Method 6: Ladybug-specific shifts (7, 14, 21...) ===")
    # Ladybug has 7 spots typically
    for multiplier in range(1, 10):
        shift_val = 7 * multiplier
        if shift_val >= 64:
            break
        try:
            shifted = shift_base64(encoded, shift_val)
            decoded = base64.b64decode(shifted)
            result = decoded.decode('utf-8', errors='ignore')
            if '07CTF{' in result:
                print(f"FOUND with ladybug shift {shift_val}: {result}")
                return result
        except:
            continue
    
    return None

if __name__ == "__main__":
    result = try_all_methods()
    if not result:
        print("\nNo flag found with standard methods. Try manual analysis or other encoding schemes.")