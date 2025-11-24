from Crypto.Cipher import AES

def solve():
    """
    Giải mã flag bằng cách đảo ngược logic kiểm tra của WASM.
    """
    
    # Khóa AES-128 (16 byte) được tìm thấy trong bộ nhớ WASM.
    key = b"OOOOHMYFAVOURITE"

    # Ciphertext bí mật (32 byte) được trích xuất từ bộ nhớ WASM.
    # Đây là giá trị mà kết quả mã hóa input của bạn được so sánh với.
    secret_ciphertext = bytes([
        0x37, 0x5a, 0x41, 0x17, 0x1a, 0x5d, 0x06, 0x06, 0x0d, 0x5b, 0x0d, 0x41, 0x5b, 0x03, 0x0c, 0x51, 
        0x5c, 0x0d, 0x06, 0x5b, 0x0d, 0x06, 0x56, 0x5f, 0x1e, 0x57, 0x0a, 0x5f, 0x0c, 0x06, 0x5e, 0x53,
        # Thêm 2 byte cuối mà các lần phân tích trước đã bỏ sót
        0x41, 0x17, 0x1a, 0x47
    ])
    
    # Cập nhật lại ciphertext chính xác sau khi rà soát kỹ file .wat
    secret_ciphertext = bytes([
        0x98, 0x9b, 0xd4, 0x7d, 0xa7, 0xbc, 0x1f, 0x54, 0xd3, 0x74, 0x95, 0x22, 0x3a, 0x0e, 0xa7, 0x7c,
        0xc1, 0x6f, 0x2b, 0x3f, 0xa6, 0xf8, 0x1d, 0xea, 0x31, 0x5d, 0x7e, 0xbd, 0x50, 0x05, 0x13, 0x23
    ])

    # Mã hóa trong WASM thường không dùng IV, nên chúng ta sẽ dùng chế độ ECB (Electronic Codebook),
    # là chế độ cơ bản nhất.
    cipher = AES.new(key, AES.MODE_ECB)
    
    # Giải mã ciphertext để tìm ra flag gốc.
    decrypted_flag_bytes = cipher.decrypt(secret_ciphertext)
    
    # In kết quả. Kết quả có thể chứa padding ở cuối, chúng ta sẽ xử lý nó.
    # .strip(b'\x00') sẽ loại bỏ các byte null thường được dùng để đệm.
    flag = decrypted_flag_bytes.strip(b'\x00').decode('utf-8')
    
    print(f"Decrypted flag: {flag}")

# Chạy hàm chính
if __name__ == "__main__":
    solve()