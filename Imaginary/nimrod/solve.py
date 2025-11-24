# Dãy byte chính xác của flag đã mã hóa từ data dump mới nhất
encrypted_bytes = [
    0x28, 0xf8, 0x3e, 0xe6, 0x3e, 0x2f, 0x43, 0x0c, 0xb9, 0x96, 0xd1, 0x5c, 0xd6, 0xbf,
    0x36, 0xd8, 0x20, 0x79, 0x0e, 0x8e, 0x52, 0x21, 0xb2, 0x50, 0xe3, 0x98, 0xb5, 0xc9,
    0xb8, 0xa0, 0x88, 0x30, 0xd9, 0x0a
]

# Seed để tạo keystream
seed = 0x13371337

# Độ dài của flag
flag_length = len(encrypted_bytes)

def generate_keystream(seed, length):
    """
    Tái hiện lại chính xác logic của hàm keystream__nimrod_20.
    Logic này đã được xác thực là đúng.
    """
    keystream = []
    
    # current_state mô phỏng biến `param_1` kiểu int 32-bit
    current_state = seed

    for _ in range(length):
        # 1. Thực hiện phép toán trên số nguyên 64-bit để tránh overflow của Python
        #    Đây là cách trình biên dịch C/C++ thường làm.
        state_64bit = current_state * 0x19660d + 0x3c6ef35f
        
        # 2. Cắt ngắn (truncate) kết quả về 32 bit để gán lại cho state
        #    & 0xFFFFFFFF tương đương với việc lấy 32 bit thấp nhất.
        current_state = state_64bit & 0xFFFFFFFF
        
        # 3. Trích xuất byte khóa: (uint)param_1 >> 0x10
        #    Lấy các bit từ 16 đến 23 của state 32-bit.
        key_byte = (current_state >> 16) & 0xFF
        keystream.append(key_byte)
        
    return keystream

# --- Chương trình chính ---

# 1. Tạo lại keystream
keystream = generate_keystream(seed, flag_length)

# 2. Giải mã flag
decrypted_flag = ""
for i in range(flag_length):
    decrypted_byte = encrypted_bytes[i] ^ keystream[i]
    decrypted_flag += chr(decrypted_byte)

print("Flag đã giải mã:")
print(decrypted_flag)