def get_flag():
    # 1. Giải mã phần đầu (Prefix) từ biến _ICE_CRYSTAL
    # Logic: XOR từng byte với 0x42
    ice_bytes = [35, 54, 33, 33, 54, 36, 29]
    prefix = "".join([chr(b ^ 0x42) for b in ice_bytes])
    
    # 2. Giải mã phần sau (Suffix) từ biến thaw_step1
    # Logic: XOR từng byte với 0x13, sau đó trừ đi 3 đơn vị ASCII
    thaw_encrypted = [96, 111, 37, 100, 120, 32, 98, 39, 101, 124, 32, 106, 37]
    
    # Bước 2a: XOR với 0x13
    thaw_step1 = [c ^ 0x13 for c in thaw_encrypted]
    
    # Bước 2b: Trừ 3 (Hàm _iced_latte trong code gốc)
    suffix = "".join([chr(c - 3) for c in thaw_step1])
    
    return prefix + suffix

def get_hidden_confession():
    # Hàm _hidden_in_snow() chứa một thông điệp ẩn khác
    _glacier = [0x4d, 0x79, 0x20, 0x77, 0x69, 0x6e, 0x74, 0x65, 0x72, 
                0x20, 0x63, 0x6f, 0x6e, 0x66, 0x65, 0x73, 0x73, 0x69,
                0x6f, 0x6e, 0x3a, 0x20]
    part1 = "".join([chr(x) for x in _glacier])
    
    _sleet = [34, 18, 18, 5, 18, 28, 84, 11, 26, 0x45, 
              19, 71, 6, 84, 24, 66, 3, 70, 17, 29, 65]
    part2 = "".join([chr(i ^ 0x42) for i in _sleet])
    
    return part1 + part2

print("Flag: " + get_flag())
print("📝 Hidden message: " + get_hidden_confession())