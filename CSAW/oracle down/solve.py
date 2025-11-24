import time
from pwn import *
from tqdm import tqdm
from Crypto.Util.Padding import unpad

# -- Cấu hình --
HOST = "15.164.102.155"
PORT = 21004

# Giảm số worker vì server có thể không xử lý nổi quá nhiều kết nối cùng lúc
# và việc brute-force giờ nhanh hơn nhiều.
WORKERS = 25 
context.log_level = 'error'

# Đọc và phân tích bản tin gốc
with open('intercepted_transmission.txt', 'r') as f:
    intercepted_hex = f.read().strip()

intercepted_bytes = bytes.fromhex(intercepted_hex)
# Dữ liệu gốc: MAC(32) + IV(16) + CIPHERTEXT(80 bytes = 5 khối)
original_iv = intercepted_bytes[32:48]
original_ciphertext = intercepted_bytes[48:]

# Chia ciphertext thành các khối 16-byte
# blocks[0] là IV, blocks[1..5] là các khối ciphertext
blocks = [original_iv] + [original_ciphertext[i:i+16] for i in range(0, len(original_ciphertext), 16)]
num_ct_blocks = len(blocks) - 1

def oracle(payload_ciph_ciph):
    """
    Gửi một payload 96-byte hoàn chỉnh.
    Chỉ phần ciph_ciph (64 bytes) được truyền vào.
    Hàm trả về True nếu phản hồi chậm (padding đúng), False nếu nhanh.
    """
    # Luôn gửi 32 byte MAC giả ở đầu
    full_payload = (b'\x00' * 32 + payload_ciph_ciph).hex().encode()
    try:
        conn = remote(HOST, PORT, timeout=3)
        start = time.time()
        conn.sendline(full_payload)
        conn.readall()
        duration = time.time() - start
        conn.close()
        # Ngưỡng 0.2s là rất an toàn để phân biệt
        return duration > 0.2
    except Exception:
        return False

def solve_block(prev_block, current_block):
    """Giải mã một khối 'current_block' bằng cách thao tác 'prev_block'."""
    decrypted_block = bytearray(16)
    
    for i in tqdm(range(15, -1, -1), desc="  -> Finding byte", leave=False):
        padding_val = 16 - i
        
        for g in range(256):
            # Tạo khối C_{i-1}' (prev_block') để tấn công
            manipulated_prev_block = bytearray(16) 
            manipulated_prev_block[i] = g
            
            # Chuẩn bị phần đuôi của khối để tạo padding mong muốn
            for j in range(i + 1, 16):
                intermediate_byte = decrypted_block[j] ^ prev_block[j]
                manipulated_prev_block[j] = intermediate_byte ^ padding_val
            
            # Xây dựng payload 64-byte hoàn chỉnh
            # ciph_ciph = IV_giả + Block1_giả + prev_block' + current_block
            payload = b'\x00'*16 + b'\x00'*16 + manipulated_prev_block + current_block
            
            if oracle(payload):
                intermediate_byte_found = g ^ padding_val
                decrypted_block[i] = intermediate_byte_found ^ prev_block[i]
                break
        else: # Nếu vòng lặp for kết thúc mà không break
             raise Exception(f"Không thể tìm thấy byte ở vị trí {i}")

    print(f"\n[+] Block decrypted: {bytes(decrypted_block)}")
    return bytes(decrypted_block)

def solve_final():
    print("[+] Bắt đầu tấn công Padding Oracle (đã sửa lỗi)...")
    plaintext = b""

    # Giải mã từ khối cuối cùng về trước
    for i in range(num_ct_blocks, 0, -1):
        print(f"\n[+] Đang giải mã khối {i}/{num_ct_blocks} (Khối gốc: C{i})")
        prev_block = blocks[i-1]   # Đây là C_{i-1}
        current_block = blocks[i]  # Đây là C_i
        
        decrypted = solve_block(prev_block, current_block)
        plaintext = decrypted + plaintext # Nối vào đầu
    
    print("\n[+] Giải mã hoàn tất!")
    print(f"[*] Plaintext (raw): {plaintext}")
    
    try:
        final_plaintext = unpad(plaintext, 16)
        print("\n" + "="*50)
        print(f"[*] FLAG: {final_plaintext.decode()}")
        print("="*50)
    except Exception as e:
        print(f"[!] Lỗi unpadding cuối cùng: {e}")
        print("[!] Có thể vẫn còn lỗi trong logic hoặc kết quả giải mã.")

if __name__ == '__main__':
    solve_final()