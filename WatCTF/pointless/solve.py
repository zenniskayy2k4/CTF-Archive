import sys

# Đặt giới hạn đệ quy cao hơn một chút để phòng ngừa
sys.setrecursionlimit(3000)

# --- Dữ liệu đã được xác minh ---
n = 56
C = [170, 161, 175, 169, 153, 114, 124, 111, 126, 172, 177, 133, 168, 149, 134, 103, 173, 151, 167, 163, 115, 176, 121, 110, 117, 148, 100, 166, 131, 118, 145, 152, 119, 174, 146, 112, 132, 162, 101, 164, 125, 98, 150, 165, 123, 102, 122, 135, 109]

# --- Script giải ---

def solve():
    print(f"[*] Bắt đầu tìm kiếm flag có độ dài n = {n}...")
    
    # Tạo chuỗi Tribonacci
    trib = [1, 2, 3]
    while len(trib) < n:
        trib.append(trib[-1] + trib[-2] + trib[-3])
    
    # Tạo một set từ C để kiểm tra nhanh
    C_set = set(C)

    # flag_bytes sẽ lưu trữ mã ASCII của flag
    flag_bytes = [-1] * n
    
    # Bắt đầu tìm kiếm quay lui
    def find_flag(k, current_combined_list):
        """
        Hàm đệ quy để tìm ký tự thứ k.
        current_combined_list: danh sách các giá trị combined đã tạo ra từ 0 đến k-1.
        """
        # Nếu đã điền đủ flag
        if k == n:
            # `dict.fromkeys` là một cách nhanh để tạo list duy nhất (nub)
            nub_combined = list(dict.fromkeys(current_combined_list))
            # Kiểm tra xem kết quả có khớp với C không
            if nub_combined == C:
                return True
            else:
                return False

        # Duyệt qua các ký tự in được (32-126)
        for char_code in range(32, 127):
            
            combined_val = char_code + trib[char_code % n]
            
            # --- Cắt tỉa (Pruning) - Rất quan trọng! ---
            # 1. Nếu giá trị combined tạo ra không có trong C, loại ngay.
            if combined_val not in C_set:
                continue

            # 2. Kiểm tra xem thứ tự có bị phá vỡ không.
            #    Tạo nub tạm thời và so sánh với phần đầu của C.
            temp_list = current_combined_list + [combined_val]
            temp_nub = list(dict.fromkeys(temp_list))
            
            # Nếu nub tạm thời không khớp với phần đầu của C, nhánh này sai.
            if temp_nub != C[:len(temp_nub)]:
                continue

            # Nếu mọi thứ đều ổn, điền ký tự vào và tiếp tục đệ quy
            flag_bytes[k] = char_code
            if find_flag(k + 1, temp_list):
                return True
        
        # Nếu không có ký tự nào ở vị trí k dẫn đến lời giải
        return False

    if find_flag(0, []):
        flag = "".join(map(chr, flag_bytes))
        print(f"\n[SUCCESS] FLAG: {flag}")
    else:
        print("\n[-] Không tìm thấy lời giải. (Điều này không nên xảy ra)")

if __name__ == '__main__':
    solve()