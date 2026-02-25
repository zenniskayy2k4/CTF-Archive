import struct
import base64
import zipfile
import os

def solve_missing_homework(apk_path):
    # 1. Giải nén AndroidManifest.xml từ APK
    manifest_path = 'AndroidManifest.xml'
    try:
        with zipfile.ZipFile(apk_path, 'r') as z:
            z.extract(manifest_path)
    except Exception as e:
        print(f"[-] Không thể giải nén APK: {e}")
        return

    # 2. Đọc và phân tích Binary XML
    try:
        with open(manifest_path, 'rb') as f:
            data = f.read()
    finally:
        if os.path.exists(manifest_path):
            os.remove(manifest_path)

    # Kiểm tra Header Binary XML
    header_type = struct.unpack('<H', data[0:2])[0]
    if header_type != 0x0003:
        print("[-] Đây không phải là file Binary XML hợp lệ.")
        return

    # 3. Trích xuất chuỗi từ String Pool
    string_pool_offset = 8
    chunk_type = struct.unpack('<H', data[string_pool_offset:string_pool_offset+2])[0]
    
    extracted_b64_chars = []
    
    if chunk_type == 0x0001:  # RES_STRING_POOL_TYPE
        string_count = struct.unpack('<I', data[string_pool_offset+8:string_pool_offset+12])[0]
        flags = struct.unpack('<I', data[string_pool_offset+16:string_pool_offset+20])[0]
        strings_start = struct.unpack('<I', data[string_pool_offset+20:string_pool_offset+24])[0]
        
        is_utf8 = (flags & (1 << 8)) != 0
        offsets = []
        for i in range(string_count):
            off = struct.unpack('<I', data[string_pool_offset+28+i*4:string_pool_offset+32+i*4])[0]
            offsets.append(string_pool_offset + strings_start + off)
            
        for start_off in offsets:
            try:
                if is_utf8:
                    # Đọc độ dài UTF-8 (đơn giản hóa)
                    length = data[start_off + 1]
                    s = data[start_off + 2:start_off + 2 + length].decode('utf-8', errors='ignore')
                else:
                    # UTF-16
                    length = struct.unpack('<H', data[start_off:start_off+2])[0]
                    s = data[start_off+2:start_off+2+length*2].decode('utf-16', errors='ignore')
                
                # Logic nhận diện: Các ký tự flag được inject lẻ tẻ thường có độ dài là 1
                if len(s) == 1:
                    # Lọc các ký tự thuộc bảng Base64
                    if s in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=":
                        extracted_b64_chars.append(s)
            except:
                continue

    # 4. Ghép nối và giải mã Flag
    if extracted_b64_chars:
        # Trong bài này, flag bắt đầu bằng 'Y' (Base64 của 'b')
        # Tìm vị trí ký tự 'Y' đầu tiên để tránh rác nếu có
        try:
            start_index = extracted_b64_chars.index('Y')
            b64_string = "".join(extracted_b64_chars[start_index:])
        except ValueError:
            b64_string = "".join(extracted_b64_chars)

        print(f"[*] Raw Base64: {b64_string}")
        
        try:
            # Thêm padding nếu thiếu
            missing_padding = len(b64_string) % 4
            if missing_padding:
                b64_string += '=' * (4 - missing_padding)
                
            flag = base64.b64decode(b64_string).decode()
            print(f"[+] FLAG: {flag}")
        except Exception as e:
            print(f"[-] Lỗi giải mã Base64: {e}")
    else:
        print("[-] Không tìm thấy chuỗi ký tự đơn lẻ nào khả nghi.")

if __name__ == "__main__":
    # Thay 'hiddenfile.apk' bằng đường dẫn file của bạn
    solve_missing_homework('hiddenfile.apk')