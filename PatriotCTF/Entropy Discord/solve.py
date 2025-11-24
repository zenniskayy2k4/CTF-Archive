import sys

def solve():
    print("[*] Bắt đầu quét tìm Flag...")
    
    # Dữ liệu mã hóa đầy đủ (bao gồm byte 0x33 bị thiếu trong ảnh trước)
    # Index:      0     1     2     3     4     5
    # Bytes:    0x33  0x87  0x08  0xB8  0xA2  0xF5  ...
    enc = [
        0x33, 0x87, 0x08, 0xb8, 0xa2, 0xf5, 0xb8, 0x04, 0x74, 0xd6, 
        0x0b, 0xe7, 0xae, 0x20, 0xe6, 0x33, 0xe7, 0xf3, 0x5d, 0xa5, 
        0xcd, 0x54, 0x02, 0x28, 0x4b, 0xfb, 0xe8, 0x7d, 0x23, 0x23
    ]

    # LCG Constants (32-bit logic as analyzed)
    MULT = 0xdeece66d
    ADD = 0xb
    MASK = 0xFFFFFFFF

    # Các header hợp lệ để nhận diện (Case-insensitive)
    VALID_HEADERS = [b'pctf', b'caci', b'flag', b'patr']

    # ---------------------------------------------------------
    # Chiến thuật Brute-force tối ưu:
    # Seed (S) sinh ra Key Byte (K) = (S >> 8) & 0xFF
    # Byte giải mã (P) = Enc ^ K
    # => K = Enc ^ P
    # => (S >> 8) & 0xFF == Enc ^ P
    # ---------------------------------------------------------

    # Bước 1: Giả định ký tự đầu tiên (Index 0) là một chữ cái in hoa hoặc thường
    # 'P', 'p', 'C', 'c', 'F', 'f', ...
    # Điều này giúp giảm không gian tìm kiếm từ 4 tỷ xuống còn vài triệu.
    
    possible_starts = []
    # Chỉ thử các ký tự đầu phổ biến của Flag
    common_first_chars = b"pPcCfF" 
    
    found_flag = False

    for char_code in common_first_chars:
        # Tính Key Byte kỳ vọng cho ký tự đầu
        target_k0 = enc[0] ^ char_code
        
        # Seed S0 phải có dạng: 0x????XX?? với XX = target_k0
        # Duyệt 16 bit cao của Seed (0-65535)
        # Duyệt 8 bit thấp của Seed (0-255)
        # Tổng: ~16 triệu khả năng (mất khoảng 5-10 giây)
        
        print(f"[*] Đang kiểm tra giả thuyết ký tự đầu là '{chr(char_code)}'...")
        
        for high16 in range(65536):
            base_s0 = (high16 << 16) | (target_k0 << 8)
            
            for low8 in range(256):
                s0 = base_s0 | low8
                
                # Kiểm tra xem chuỗi tạo ra có hợp lệ không
                # Giải mã thử 4 byte đầu
                curr = s0
                decoded = bytearray()
                
                # Byte 0 (Đã khớp do cách chọn s0)
                decoded.append(char_code)
                
                # Byte 1
                s1 = (curr * MULT + ADD) & MASK
                k1 = (s1 >> 8) & 0xFF
                p1 = enc[1] ^ k1
                decoded.append(p1)
                
                # Byte 2
                s2 = (s1 * MULT + ADD) & MASK
                k2 = (s2 >> 8) & 0xFF
                p2 = enc[2] ^ k2
                decoded.append(p2)
                
                # Byte 3
                s3 = (s2 * MULT + ADD) & MASK
                k3 = (s3 >> 8) & 0xFF
                p3 = enc[3] ^ k3
                decoded.append(p3)
                
                # Kiểm tra Header
                check_str = decoded.lower()
                if any(check_str.startswith(h) for h in VALID_HEADERS):
                    # Nếu khớp header, giải mã toàn bộ
                    full_flag = ""
                    temp_s = s0
                    
                    # Giải mã lại từ đầu (bao gồm byte 0)
                    # Lưu ý: Vòng lặp trong ASM update seed TRƯỚC khi decrypt
                    # Nhưng ta đang tìm s0 là trạng thái *sau* khi update lần 1
                    # Nên ta dùng s0 decrypt byte 0, s1 decrypt byte 1...
                    
                    t_state = s0
                    # Byte 0
                    k = (t_state >> 8) & 0xFF
                    full_flag += chr(enc[0] ^ k)
                    
                    # Các byte còn lại
                    for i in range(1, len(enc)):
                        t_state = (t_state * MULT + ADD) & MASK
                        k = (t_state >> 8) & 0xFF
                        full_flag += chr(enc[i] ^ k)
                    
                    print(f"\n[!!!] FOUND FLAG: {full_flag}")
                    found_flag = True
                    return

    if not found_flag:
        print("[-] Không tìm thấy flag với các header thông thường.")

if __name__ == "__main__":
    solve()