import re
import sys

# 1. Cấu hình & Dữ liệu
phonetic_map = {"A":"ALPHA","B":"BRAVO","C":"CHARLIE","D":"DELTA","E":"ECHO","F":"FOXTROT","G":"GOLF","H":"HOTEL","I":"INDIA","J":"JULIETT","K":"KILO","L":"LIMA","M":"MIKE","N":"NOVEMBER","O":"OSCAR","P":"PAPA","Q":"QUEBEC","R":"ROMEO","S":"SIERRA","T":"TANGO","U":"UNIFORM","V":"VICTOR","W":"WHISKEY","X":"XRAY","Y":"YANKEE","Z":"ZULU","_":"UNDERSCORE","{":"OPENCURLYBRACE","}":"CLOSECURLYBRACE","0":"ZERO","1":"ONE","2":"TWO","3":"THREE","4":"FOUR","5":"FIVE","6":"SIX","7":"SEVEN","8":"EIGHT","9":"NINE"}
charset = "abcdefghijklmnopqrstuvwxyz0123456789_{}"

# Load ciphertext
try:
    with open("ct.txt", "r") as f:
        ct_data = f.read().strip()
    # Kiểm tra tính hợp lệ của CT
    if len(ct_data) % 2 != 0:
        print(f"[!] CẢNH BÁO: Độ dài ct.txt là lẻ ({len(ct_data)}). Có thể file bị lỗi hoặc thiếu ký tự cuối.")
    ct = [ct_data[i:i+2] for i in range(0, len(ct_data), 2)]
except FileNotFoundError:
    print("[-] Không tìm thấy file ct.txt")
    sys.exit(1)

# Tiền tính toán chuỗi L2 cho từng ký tự
def get_l2_raw(char):
    # L1 word (ví dụ: "l" -> "LIMA")
    l1_word = phonetic_map[char.upper()]
    # L2 raw string (ví dụ: "LIMA" -> "LIMAINDIAMIKEALPHA")
    # Lưu ý: KHÔNG thêm X ở đây, X chỉ thêm ở cuối cùng của toàn bộ chuỗi
    return "".join(phonetic_map[c] for c in l1_word)

l2_chunks = {c: get_l2_raw(c) for c in charset}

def solve():
    # Stack: (ct_idx, flag_so_far, l2_buffer, mapping, used_values)
    # l2_buffer: Chứa các ký tự L2 chưa đủ cặp bigram từ bước trước
    stack = [(0, "", "", {}, set())]
    
    print(f"[*] Bắt đầu giải mã với {len(ct)} bigrams...")
    max_depth = 0
    
    while stack:
        ct_idx, flag, buf, mapping, used = stack.pop()
        
        # Tracking độ sâu để biết script đang chạy
        if len(flag) > max_depth:
            max_depth = len(flag)
            print(f"    -> Đang thử độ dài {max_depth}: {flag}")

        # ĐIỀU KIỆN DỪNG & KIỂM TRA PADDING CUỐI CÙNG
        if ct_idx >= len(ct):
            # Nếu đã khớp hết CT, kiểm tra xem Flag có hợp lệ không
            # 1. Kiểm tra Padding L1
            temp_l1 = "".join(phonetic_map[c.upper()] for c in flag)
            if len(temp_l1) % 2 == 1: temp_l1 += "X"
            
            # 2. Kiểm tra Padding L2 (Final check)
            # Reconstruct lại toàn bộ để chắc chắn
            full_l2 = "".join(phonetic_map[c] for c in temp_l1)
            if len(full_l2) % 2 == 1: full_l2 += "X"
            
            # So khớp lại lần cuối
            final_bgs = [full_l2[i:i+2] for i in range(0, len(full_l2), 2)]
            
            if len(final_bgs) != len(ct):
                # Độ dài không khớp (do padding X sinh ra thêm bigram mà CT không có, hoặc ngược lại)
                continue
                
            # Kiểm tra mapping lần cuối
            valid = True
            for i in range(len(ct)):
                c_bg, p_bg = ct[i], final_bgs[i]
                if c_bg in mapping and mapping[c_bg] != p_bg: valid = False; break
                if c_bg not in mapping and p_bg in used: valid = False; break
            
            if valid: return flag
            continue

        # CHỌN KÝ TỰ TIẾP THEO
        # Ưu tiên khớp prefix "lactf{"
        next_chars = charset
        if len(flag) < 6:
            target = "lactf{"[len(flag)]
            next_chars = [target]

        for char in next_chars:
            chunk = l2_chunks[char]
            combined = buf + chunk
            
            # Tách bigram từ phần combined
            # Giữ lại phần dư (nếu lẻ) vào next_buf
            num_bgs = len(combined) // 2
            current_bgs = [combined[i*2 : (i+1)*2] for i in range(num_bgs)]
            next_buf = combined[num_bgs*2 :]
            
            # Kiểm tra độ dài tràn CT
            if ct_idx + num_bgs > len(ct):
                continue
                
            # KIỂM TRA TÍNH NHẤT QUÁN MAPPING
            new_map = mapping.copy()
            new_used = used.copy()
            possible = True
            
            for i, p_bg in enumerate(current_bgs):
                c_bg = ct[ct_idx + i]
                
                # Check Forward Mapping (CT -> PT)
                if c_bg in new_map:
                    if new_map[c_bg] != p_bg:
                        possible = False; break
                # Check Backward Mapping (PT đã được dùng cho CT khác chưa?)
                else:
                    if p_bg in new_used:
                        possible = False; break
                    new_map[c_bg] = p_bg
                    new_used.add(p_bg)
            
            if possible:
                # Đẩy vào stack: cập nhật index mới, flag mới, buffer mới
                stack.append((ct_idx + num_bgs, flag + char, next_buf, new_map, new_used))

    return None

result = solve()

if result:
    print(f"\n[+] TÌM THẤY FLAG: {result}")
else:
    print("\n[-] Không tìm thấy Flag. Có thể do:")
    print("    1. ct.txt bị lỗi/thiếu.")
    print("    2. Flag chứa ký tự không nằm trong charset (a-z0-9_{}).")
    print("    3. Logic Padding X ở cuối cùng có vấn đề với dữ liệu thực tế.")