# Đây là một hàm giả lập cho bộ tạo số giả ngẫu nhiên FUN_140002b70
def prng_update(key_val):
    key_val = (key_val ^ (key_val << 0xd)) & 0xFFFFFFFF
    key_val = (key_val ^ (key_val >> 0x11)) & 0xFFFFFFFF
    key_val = (key_val ^ (key_val << 5)) & 0xFFFFFFFF
    return key_val % 0x7fffffff

# Mô phỏng lại hàm giải mã stream cipher FUN_140001ff0
def decrypt_stream(initial_key, encrypted_data):
    decrypted = bytearray()
    current_key = initial_key
    
    for byte in encrypted_data:
        decrypted_byte = byte ^ (current_key & 0xFF)
        decrypted.append(decrypted_byte)
        current_key = prng_update(current_key)
        
    return decrypted

# Dữ liệu được trích xuất từ hàm FUN_140001580 trong IDA/Ghidra
# Đây là khối dữ liệu chứa flag đã bị mã hóa
encrypted_flag_data = bytes([
    0x96, 0x1a, 0xe9, 0x6c, 0xe2, 0x0b, 0x78, 0x3d,
    0x10, 0x29, 0x77, 0x04, 0xec, 0x62, 0x60, 0xb4,
    0x96, 0x1a, 0xe9, 0x6c
])

# Key khởi tạo cũng được hardcode trong hàm
initial_key = 0xa1d70ad0

# Thực hiện giải mã
flag_bytes = decrypt_stream(initial_key, encrypted_flag_data)

# In ra flag
# Có thể có một vài byte rác ở cuối, chúng ta chỉ lấy phần có thể in được
try:
    flag_str = flag_bytes.decode('ascii').strip('\x00')
    print(f"Flag: {flag_str}")
except UnicodeDecodeError:
    print(f"Decrypted bytes (might contain non-ascii): {flag_bytes}")