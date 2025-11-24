def solve():
    """
    Tái hiện lại thuật toán giải mã từ hàm FUN_00401050
    với dữ liệu bạn đã cung cấp.
    """
    
    # Dữ liệu 42 bytes từ DAT_00403040
    encrypted_data = bytes([
        0x33, 0x21, 0x00, 0x6d, 0x5f, 0xab, 0x86, 0xb4, 0xd4, 0x2d, 0x36, 0x3a, 0x4e, 0x90, 0x8c, 0xe3,
        0xcc, 0x2e, 0x09, 0x6c, 0x49, 0xb8, 0x8f, 0xf7, 0xcc, 0x22, 0x4e, 0x4d, 0x5e, 0xb8, 0x80, 0xcb,
        0xd3, 0xda, 0x20, 0x29, 0x70, 0x02, 0xb7, 0xd1, 0xb7, 0xc4
    ])
    
    decrypted_data = bytearray(0x2a)
    bVar6 = 0
    
    for i in range(0x2a):
        # Lấy byte gốc
        original_byte = encrypted_data[i]
        
        # Giải mã theo logic trong hàm main:
        # 1. bVar1 = original_byte ^ bVar6
        bVar1 = original_byte ^ bVar6
        
        # 2. Cập nhật bVar6 cho lần lặp sau (sử dụng & 0xFF để đảm bảo là 1 byte)
        bVar6 = (bVar6 + 0x1f) & 0xFF
        
        # 3. XOR lần cuối để có byte đã giải mã
        # result = bVar1 ^ (i >> 1) ^ 0x5a
        decrypted_byte = bVar1 ^ (i >> 1) ^ 0x5a
        
        decrypted_data[i] = decrypted_byte
        
    # Chuyển kết quả thành chuỗi
    flag = decrypted_data.decode('utf-8')
    
    print("\n[+] Dữ liệu đã được giải mã thành công!")
    print(f"[+] Flag/Password là: {flag}")

if __name__ == "__main__":
    solve()