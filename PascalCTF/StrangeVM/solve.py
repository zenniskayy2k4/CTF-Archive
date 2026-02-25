def solve_final():
    # Dữ liệu dump từ GDB (x/40bx 0x4a0278)
    encoded_bytes = [
        0x56, 0x4c, 0x75, 0x5c, 0x38, 0x6d, 0x39, 0x58,  # 0-7
        0x6c, 0x28, 0x3e, 0x57, 0x7b, 0x5f, 0x3f, 0x54,  # 8-15
        0x44, 0x5b, 0x71, 0x20, 0x82, 0x1b, 0x8b, 0x50,  # 16-23
        0x80, 0x46, 0x7e, 0x15, 0x8a, 0x57, 0x7d, 0x5a,  # 24-31
        0x50, 0x54, 0x81, 0x51, 0x8c, 0x0c, 0x94, 0x44   # 32-39
    ]

    flag = ""
    for i in range(len(encoded_bytes)):
        val = encoded_bytes[i]
        decoded = 0
        
        # Logic đảo ngược:
        # Nếu index chẵn: Encoded = Input + i  => Input = Encoded - i
        # Nếu index lẻ:   Encoded = Input - i  => Input = Encoded + i
        
        if i % 2 == 0:
            decoded = (val - i) & 0xFF 
        else:
            decoded = (val + i) & 0xFF
            
        flag += chr(decoded)

    print("Flag:", f"pascalCTF{{{flag}}}")

if __name__ == "__main__":
    solve_final()