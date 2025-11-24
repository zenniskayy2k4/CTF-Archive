import struct

# Dữ liệu tĩnh được trích xuất từ file thực thi của challenge
PERMUTATION_TABLE = bytes([
    0x0d, 0x08, 0x11, 0x0c, 0x0e, 0x07, 0x00, 0x05,
    0x09, 0x04, 0x0b, 0x10, 0x06, 0x12, 0x0a, 0x01,
    0x02, 0x03, 0x0f, 0x13
])

XOR_TABLE = bytes([
    0xba, 0x79, 0xce, 0x55, 0x64, 0x13, 0x62, 0x21, 0xbf, 0xcc, 0x96, 0x0f, 0x68, 0x95, 0x2d, 0x51,
    0x7a, 0x59, 0xf6, 0x44, 0xe5, 0x43, 0x3e, 0xb3, 0xa3, 0x81, 0x4f, 0xa6, 0x36, 0xfb, 0x6d, 0xf8,
    0xf7, 0x1f, 0x6b, 0x42, 0xa7, 0xb7, 0xbc, 0x71, 0x0d, 0xb4, 0xe0, 0xb9, 0x25, 0x0a, 0x28, 0xa1,
    0x76, 0x86, 0x6c, 0x27, 0xd9, 0x2a, 0x6a, 0x03, 0xf1, 0x72, 0xdb, 0x54, 0x82, 0x6f, 0xbb, 0x1c,
    0x5a, 0x38, 0xd2, 0xbe, 0x09, 0x9b, 0x15, 0xb8, 0x8f, 0x78, 0x4c, 0x34, 0x67, 0xd7, 0xab, 0x75,
    0x45, 0x87, 0x9d, 0x10, 0xe8, 0xeb, 0x32, 0x8d, 0xc5, 0x46, 0x65, 0x0b, 0x35, 0xbd, 0xea, 0x06,
    0xa5, 0xdd, 0xa4, 0x5f, 0x40, 0x5d, 0xfc, 0x9a, 0x5b, 0xcb, 0x89, 0x91, 0x5c, 0xfe, 0x66, 0xfd,
    0xaa, 0x37, 0x02, 0x12, 0x98, 0x6e, 0x17, 0xc9, 0x50, 0x20, 0x39, 0xc2, 0xed, 0xe7, 0xb2, 0x74,
    0xe2, 0xef, 0x16, 0x5e, 0x99, 0x47, 0xf5, 0x1e, 0x23, 0x01, 0x57, 0xa0, 0x3b, 0x1b, 0x2b, 0xee,
    0xc1, 0x58, 0x9e, 0xa9, 0xca, 0xff, 0xc4, 0x7b, 0x4b, 0x8e, 0x48, 0xcd, 0x7c, 0xc0, 0x56, 0xd0,
    0x33, 0xc7, 0x70, 0x8b, 0xe1, 0x8c, 0xc3, 0x0e, 0x1d, 0x3d, 0xda, 0xcf, 0x11, 0x73, 0xec, 0xc6,
    0x92, 0xb6, 0x26, 0x05, 0xfa, 0xf0, 0xe6, 0x0c, 0x14, 0x69, 0x61, 0xc8, 0x60, 0x31, 0x9c, 0x22,
    0xac, 0x9f, 0x4e, 0x49, 0x29, 0x3f, 0x85, 0xf3, 0x53, 0xf9, 0x63, 0xdf, 0xd3, 0xf2, 0x00, 0x2e,
    0x18, 0xd1, 0xde, 0x8a, 0x52, 0x08, 0xe9, 0xa2, 0xe4, 0x3a, 0x83, 0x7f, 0x94, 0xb5, 0xd4, 0xd5,
    0x77, 0x07, 0xdc, 0x19, 0x84, 0xd8, 0xaf, 0xa8, 0x93, 0x7e, 0xd6, 0x2c, 0xf4, 0x41, 0xb1, 0x2f,
    0x7d, 0x4d, 0x97, 0x1a, 0x3c, 0xb0, 0x80, 0x90, 0x4a, 0xae, 0x24, 0x88, 0xad, 0x04, 0x30, 0xe3
])

def rotl(x, n):
    return ((x << (n & 0x1f)) | (x >> (32 - (n & 0x1f)))) & 0xFFFFFFFF

def generate_key(seed):
    temp_buf = [0] * 20
    current_val = seed
    for i in range(20):
        temp_buf[i] = current_val
        current_val = rotl(current_val, current_val & 0xf)
    for i in range(20):
        idx_to_swap = PERMUTATION_TABLE[i]
        temp_buf[i], temp_buf[idx_to_swap] = temp_buf[idx_to_swap], temp_buf[i]
    key_material = bytearray(b''.join(struct.pack('<I', val) for val in temp_buf))
    
    # === PHẦN SỬA LỖI NẰM Ở ĐÂY ===
    prev_byte = 0
    for i in range(80):
        current_byte_val = key_material[i]
        # Tính toán giá trị byte mới
        new_byte = XOR_TABLE[current_byte_val] ^ prev_byte
        # Gán giá trị mới
        key_material[i] = new_byte
        # Cập nhật prev_byte bằng giá trị MỚI
        prev_byte = new_byte
        
    return bytes(key_material)

def rc4_decrypt(key, data):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = 0
    j = 0
    result = bytearray()
    for char in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        keystream_byte = S[(S[i] + S[j]) % 256]
        result.append(char ^ keystream_byte)
    return bytes(result)

def process_stream(stream_name, stream_hex):
    print(f"\n--- Phân tích {stream_name} ---")
    data = bytes.fromhex(stream_hex)
    cursor = 0
    msg_count = 1
    while cursor < len(data):
        if len(data) - cursor < 8: break
        seed = struct.unpack('<I', data[cursor:cursor+4])[0]
        length = struct.unpack('<I', data[cursor+4:cursor+8])[0]
        cursor += 8
        ciphertext = data[cursor:cursor+length]
        cursor += length
        key = generate_key(seed)
        plaintext = rc4_decrypt(key, ciphertext)
        print(f"\n[Gói tin #{msg_count}]")
        print(f"  Seed: {hex(seed)}, Length: {length}")
        try:
            msg_type = plaintext[0]
            if msg_type == 0:
                user_len = plaintext[1]
                user = plaintext[2 : 2+user_len].decode()
                pass_len = plaintext[2+user_len]
                password = plaintext[3+user_len : 3+user_len+pass_len].decode()
                print(f"  Loại: Login Attempt")
                print(f"  [C->S] User: '{user}', Pass: '{password}'")
            elif msg_type == 1:
                print(f"  Loại: Login Response")
                print(f"  [S->C] Login successful!")
            elif msg_type == 2 or msg_type == 3:
                sender_len = plaintext[1]
                sender = plaintext[2 : 2+sender_len].decode()
                message_len = plaintext[2+sender_len]
                message = plaintext[3+sender_len : 3+sender_len+message_len].decode()
                direction = "[C->S]" if stream_name == "Stream 0 (Client to Server)" else "[S->C]"
                print(f"  Loại: Chat Message")
                print(f"  {direction} From: '{sender}', Message: '{message}'")
            else:
                print(f"  Không thể phân tích plaintext (loại tin nhắn không xác định): {plaintext.hex()}")
        except Exception:
            print(f"  Lỗi khi phân tích plaintext, Raw: {plaintext.hex()}")
        msg_count += 1

stream_0_hex = "c6237f77200000007eba8d0f617bf90990dad469793c700fa16724ea028c3d4db57e0c80a077e0d55961965e01000000f243a72f7d4f0000000e6bcbc2f22c2ab292df5214621f539fb64957e5bc263200363280f254c9cef412c3daed1bca89945c4c8de150da6353ec04eb2c44aafb21841041f8dc032f7f31ed4a3d50477a9c5e96ba2c22a88e7fc8fe7f48000000f31cd383bb6fdd8f41a8924099f79eda967f039fda8253b668843bd32cd8e6b085cd34f14563a3534c61b78e81c2246ed231daa7e93fba5634fe344c0524b1922569b8de54f391ba"
stream_1_hex = "c6237f771e0000007ea59e09676df10f96d7c56178357c18c951338a3e953a5dbb470cc3e1640e4004130100000037e1f9fff7520000009be5551aa580c8491f538a5dc2993663948023fa7bc0e47501aa37562dae954fcc2951406fa878ca7d1666bfd23f161ea71fb7bf3bf7f19a81e28608b39e299fe215d8300eadbdf801a49bda9078237f1c309b5fa5e44b000000f420fae91d6e90512b260b75da9a437afec536fb674f55f31d20817de08fac62f8e4ee1fb5e5e587924210d555a5bb2ed5e1c3efc6521b151c6cbd9e94119bd906e5557a30158758b815d6"

process_stream("Stream 0 (Client to Server)", stream_0_hex)
process_stream("Stream 1 (Server to Client)", stream_1_hex)