from pwn import *
import time
import sys

context.timeout = 15

def get_new_problem():
    while True:
        try:
            r = remote("challs.watctf.org", 2013)
            original_hex = r.recvline().strip().decode()
            original_bytes = bytes.fromhex(original_hex)
            r.recvuntil(b'> ')
            log.info(f"Got new problem set: {original_hex[:32]}...")
            return r, original_bytes
        except (PwnlibException, ValueError, IndexError, EOFError) as e:
            log.warning(f"Failed to get problem, retrying in 3 seconds... ({e})")
            time.sleep(3)

BLOCK_SIZE = 16

def check_padding(r, iv: bytes, ct: bytes) -> bool:
    payload = (iv + ct).hex()
    r.sendline(payload.encode())
    time.sleep(0.1)
    response = r.recvline(timeout=10).strip().decode()
    if not response:
        raise EOFError("Server closed connection (empty response).")
    return "Valid padding" in response

_, temp_bytes = get_new_problem()
if not temp_bytes: exit()
num_total_blocks = len(temp_bytes) // BLOCK_SIZE
final_plaintext = b''

for block_to_solve_idx in range(num_total_blocks - 1, 0, -1):
    
    decrypted_block = None
    
    while decrypted_block is None:
        
        r, original_bytes = get_new_problem()
        if not r:
            time.sleep(2); continue

        all_blocks = [original_bytes[i:i+BLOCK_SIZE] for i in range(0, len(original_bytes), BLOCK_SIZE)]
        target_block = all_blocks[block_to_solve_idx]
        prev_block_orig = all_blocks[block_to_solve_idx - 1]
        
        intermediate_state = bytearray(BLOCK_SIZE)
        current_decrypted_block = bytearray(BLOCK_SIZE)
        
        log.info(f"Attempting to solve block {block_to_solve_idx} with new problem set...")
        
        try:
            for byte_idx in range(BLOCK_SIZE - 1, -1, -1):
                pad_val = BLOCK_SIZE - byte_idx
                mangling_iv = bytearray(b'\x00' * BLOCK_SIZE)
                
                for i in range(byte_idx + 1, BLOCK_SIZE):
                    mangling_iv[i] = intermediate_state[i] ^ pad_val
                    
                found = False
                for g in range(256):
                    mangling_iv[byte_idx] = g
                    
                    if check_padding(r, bytes(mangling_iv), target_block):
                        if pad_val == 1:
                            test_iv = bytearray(mangling_iv)
                            test_iv[byte_idx - 1] ^= 0x80
                            if not check_padding(r, bytes(test_iv), target_block):
                                continue

                        intermediate_state[byte_idx] = g ^ pad_val
                        current_decrypted_block[byte_idx] = intermediate_state[byte_idx] ^ prev_block_orig[byte_idx]
                        found = True
                        break
                
                if not found:
                    raise Exception(f"Brute force failed for byte {byte_idx}")

                progress_str = ''.join(f'\\x{b:02x}' for b in current_decrypted_block)
                sys.stdout.write(f"\r  Progress: {progress_str}")
                sys.stdout.flush()

            decrypted_block = bytes(current_decrypted_block)
            log.success(f"\nBlock {block_to_solve_idx} solved!")

        except (EOFError, PwnlibException, Exception) as e:
            log.warning(f"\nSession interrupted: {e}. Restarting for this block.")
            if r:
                r.close()
            time.sleep(2)

    final_plaintext = decrypted_block + final_plaintext

log.success("All blocks have been decrypted!")
log.info(f"Raw decrypted data (hex): {final_plaintext.hex()}")

try:
    pad_len = final_plaintext[-1]
    if pad_len > 0 and pad_len <= BLOCK_SIZE:
        padding = bytes([pad_len]) * pad_len
        if final_plaintext.endswith(padding):
            unpadded_plaintext = final_plaintext[:-pad_len]
            log.success(f"Flag (JSON): {unpadded_plaintext.decode('utf-8')}")
        else:
            log.error("Final plaintext has incorrect padding.")
    else:
        log.error(f"Invalid final padding byte value: {pad_len}")
except (IndexError, UnicodeDecodeError) as e:
    log.error(f"Failed to unpad or decode: {e}")