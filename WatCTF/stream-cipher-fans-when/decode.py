import numpy as np

CHUNK_SIZE = 256

def apply_perm(chunk, perm):
    assert len(chunk) == CHUNK_SIZE
    return np.array(list(chunk), dtype=np.uint8)[perm]

def chf(data, perm):
    state = np.zeros(CHUNK_SIZE, dtype=np.uint8)
    for i in range(0, len(data), CHUNK_SIZE):
        chunk = data[i:i+CHUNK_SIZE]
        chunk += b'\0'*(CHUNK_SIZE-len(chunk))
        state ^= apply_perm(chunk, perm)
    return bytes(state.tolist())

def csprng(perm):
    counter = 0
    while True:
        block = chf((1337*str(counter)).encode(), perm)
        yield block
        counter += 1

def decrypt_with_perm(encrypted_data, perm):
    decrypted = b""
    gen = csprng(perm)
    
    for i in range(0, len(encrypted_data), CHUNK_SIZE):
        cipher_block = encrypted_data[i:i+CHUNK_SIZE]
        if len(cipher_block) == 0:
            break
        
        enc_block = next(gen)
        plain_block = bytes([x^y for x,y in zip(cipher_block, enc_block)])
        decrypted += plain_block
    
    return decrypted

def manual_flag_search():
    print("=== Manual Flag Search ===\n")
    
    # Load and decrypt
    with open('encrypted.bin', 'rb') as f:
        encrypted_data = f.read()
    
    np.random.seed(0)
    perm = np.random.permutation(np.arange(CHUNK_SIZE))
    decrypted = decrypt_with_perm(encrypted_data, perm)
    
    print(f"Decrypted {len(decrypted)} bytes\n")
    
    # Search for all { characters
    brace_positions = []
    for i, byte in enumerate(decrypted):
        if byte == ord('{'):
            brace_positions.append(i)
    
    print(f"Found {len(brace_positions)} opening braces\n")
    
    # Check each brace for potential flags
    potential_flags = []
    
    for pos in brace_positions:
        # Look backwards for potential flag prefix
        start_search = max(0, pos - 20)
        prefix_area = decrypted[start_search:pos]
        
        # Look forward for closing brace
        end_pos = None
        for i in range(pos + 1, min(len(decrypted), pos + 200)):  # Max 200 chars for flag
            if decrypted[i] == ord('}'):
                end_pos = i
                break
        
        if end_pos is not None:
            # Extract the complete potential flag with context
            full_context = decrypted[start_search:end_pos+1]
            flag_content = decrypted[pos:end_pos+1]
            
            potential_flags.append({
                'position': pos,
                'context': full_context,
                'flag': flag_content,
                'prefix_area': prefix_area
            })
    
    print("POTENTIAL FLAG CANDIDATES:\n")
    
    for i, candidate in enumerate(potential_flags):
        print(f"Candidate {i+1} at position {candidate['position']}:")
        
        try:
            context_str = candidate['context'].decode('utf-8', errors='replace')
            flag_str = candidate['flag'].decode('utf-8', errors='replace')
            prefix_str = candidate['prefix_area'].decode('utf-8', errors='replace')
            
            print(f"  Context: {context_str}")
            print(f"  Flag part: {flag_str}")
            print(f"  Prefix area: {prefix_str}")
            
            # Score this candidate
            score = 0
            
            # Check for flag-like prefixes in context
            context_lower = context_str.lower()
            if 'watctf' in context_lower: score += 10
            if 'flag' in context_lower: score += 8
            if 'ctf' in context_lower: score += 6
            
            # Check flag length (reasonable flags are 20-80 chars)
            flag_len = len(flag_str)
            if 20 <= flag_len <= 80: score += 5
            elif 10 <= flag_len <= 100: score += 3
            
            # Check for reasonable characters in flag
            printable_chars = sum(1 for c in flag_str if c.isprintable() and ord(c) < 128)
            printable_ratio = printable_chars / len(flag_str)
            if printable_ratio > 0.8: score += 5
            elif printable_ratio > 0.6: score += 3
            
            print(f"  Score: {score}")
            
            if score >= 8:
                print(f"  ⭐ HIGH PROBABILITY FLAG!")
                
                # Try to clean it up
                cleaned = ''.join(c for c in flag_str if c.isprintable())
                print(f"  Cleaned: {cleaned}")
                
                # Check if prefix suggests this is the real flag
                if any(word in prefix_str.lower() for word in ['watevr', 'flag']):
                    print(f"  🚩 VERY LIKELY THE REAL FLAG: {cleaned}")
            
            print()
            
        except Exception as e:
            print(f"  Error decoding: {e}")
            print(f"  Raw bytes: {candidate['flag'][:50]}...")
            print()
    
    print("\n" + "="*60)
    print("ADDITIONAL ANALYSIS:")
    print("="*60)
    
    # Try to find the exact corruption pattern
    # We know from the regex that we saw "hFlgr{" which might be "watevr{"
    corruption_map = {}
    
    # Look for the specific pattern we saw
    target_pattern = "hFlgr{ f^J XG"
    
    for i in range(len(decrypted) - len(target_pattern.encode())):
        chunk = decrypted[i:i+len(target_pattern.encode())]
        try:
            chunk_str = chunk.decode('utf-8', errors='replace')
            if 'Flgr' in chunk_str or 'flgr' in chunk_str:
                print(f"Found similar pattern at {i}: {chunk_str}")
                
                # Try to extract full flag from here
                end_pos = decrypted.find(ord('}'), i)
                if end_pos != -1:
                    full_flag = decrypted[i:end_pos+1]
                    print(f"Full flag candidate: {full_flag}")
                    try:
                        decoded_flag = full_flag.decode('utf-8', errors='replace')
                        print(f"Decoded: {decoded_flag}")
                        
                        # Try manual character substitution
                        manual_fix = decoded_flag
                        substitutions = {
                            'hFlgr{': 'watevr{',
                            'Flgr{': 'flag{',
                            '^': 'o',
                            '¶': 'a',
                            '‼': 'n',
                            '\\|': 'l',
                        }
                        
                        for old, new in substitutions.items():
                            manual_fix = manual_fix.replace(old, new)
                        
                        print(f"Manual fix attempt: {manual_fix}")
                        
                    except Exception as e:
                        print(f"Decode error: {e}")
        except:
            continue
    
    # One more attempt: hexdump search
    print(f"\nHEX SEARCH FOR WATEVR PATTERN:")
    watevr_hex = b'watevr{'.hex()
    decrypted_hex = decrypted.hex()
    
    if watevr_hex in decrypted_hex:
        pos = decrypted_hex.find(watevr_hex)
        byte_pos = pos // 2
        print(f"Found 'watevr{{' at byte position {byte_pos}")
        
        flag_start = byte_pos
        flag_end = decrypted.find(ord('}'), flag_start)
        
        if flag_end != -1:
            real_flag = decrypted[flag_start:flag_end+1]
            print(f"REAL FLAG FOUND: {real_flag}")
            try:
                print(f"DECODED FLAG: {real_flag.decode('utf-8')}")
            except:
                print(f"DECODED FLAG (latin-1): {real_flag.decode('latin-1', errors='replace')}")
    else:
        print("Direct 'watevr{' pattern not found in hex")

if __name__ == "__main__":
    manual_flag_search()