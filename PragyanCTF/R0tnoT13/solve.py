from Crypto.Util.number import long_to_bytes

states = {
    8: 183552667878302390742187834892988820241,
    4: 303499033263465715696839767032360064630,
    16: 206844958160238142919064580247611979450,
    2: 163378902990129536295589118329764595602,
    64: 105702179473185502572235663113526159091,
    32: 230156190944614555973250270591375837085
}

ciphertext_hex = "477eb79b46ef667f16ddd94ca933c7c0"
ciphertext = bytes.fromhex(ciphertext_hex)

# Hàm lấy bit thứ i của số nguyên (0 là LSB)
def get_bit(val, i):
    return (val >> i) & 1

# Giá trị chênh lệch (diff) khi k=2
# Phương trình: s[i] ^ s[i+2] = bit_i_của_val
diff_val = states[2]

# Brute-force 2 bit neo (s0 và s1)
for s0 in [0, 1]:
    for s1 in [0, 1]:
        # Khởi tạo mảng bit cho State
        s = [0] * 128
        
        # Gán 2 bit neo đã đoán
        s[0] = s0
        s[1] = s1
        
        # Khôi phục chuỗi chẵn: 0 -> 2 -> 4 ... -> 126
        # Công thức: s[i+2] = s[i] ^ diff_bit_i
        for i in range(0, 126, 2): # Dừng ở 126 vì 126+2 = 128 (về 0)
             s[i+2] = s[i] ^ get_bit(diff_val, i)
             
        # Khôi phục chuỗi lẻ: 1 -> 3 -> 5 ... -> 127
        for i in range(1, 127, 2):
             s[i+2] = s[i] ^ get_bit(diff_val, i)
             
        # Chuyển mảng bit thành số nguyên S
        S_int = 0
        for i in range(128):
            S_int |= (s[i] << i)
            
        # Chuyển S thành bytes để giải mã
        try:
            S_bytes = long_to_bytes(S_int, 16)
            # Padding nếu S nhỏ hơn 16 bytes (ít gặp nhưng đề phòng)
            S_bytes = S_bytes.rjust(16, b'\x00') 
            
            # Thử giải mã bằng XOR: Flag = Ciphertext ^ State
            decrypted = bytes([c ^ k for c, k in zip(ciphertext, S_bytes)])
            
            # Kiểm tra xem kết quả có in được không (dấu hiệu của Flag)
            # Flag thường chứa các ký tự ASCII đọc được
            if all(32 <= b <= 126 for b in decrypted):
                print(f"[+] Found candidate (s0={s0}, s1={s1}):")
                print(f"    Hex State: {hex(S_int)}")
                print(f"    Flag: {decrypted.decode()}")
        except Exception as e:
            continue