import zlib
import re

def final_hunt(file_path):
    with open(file_path, 'rb') as f:
        data = f.read()

    # 1. Trích xuất toàn bộ IDAT
    raw_idats = b""
    pos = 0
    while True:
        pos = data.find(b'IDAT', pos)
        if pos == -1: break
        import struct
        length = struct.unpack('>I', data[pos-4:pos])[0]
        raw_idats += data[pos+4 : pos+4+length]
        pos += 4 + length
    
    try:
        decompressed = zlib.decompress(raw_idats)
        print(f"[*] Đã giải nén thành công {len(decompressed)} bytes.")
    except:
        print("[-] Không thể giải nén IDAT.")
        return

    # 2. Tìm flag dạng nhân ba (000xxxfffuuunnn{{{...}}})
    # Chúng ta tìm mẫu '000xxxfff'
    tripled_pattern = b'000xxxfffuuunnn{{{'
    idx = decompressed.find(tripled_pattern)
    if idx != -1:
        print("[!] Tìm thấy Flag dạng nhân ba!")
        end_idx = decompressed.find(b'}}}', idx) + 3
        tripled_flag = decompressed[idx:end_idx]
        # Khôi phục từ nhân ba
        flag = "".join([chr(tripled_flag[i]) for i in range(0, len(tripled_flag), 3)])
        print(f"==> FLAG: {flag}")
        return

    # 3. Tìm flag dạng thường (0xfun{...})
    match = re.search(b'0xfun\{.*?\}', decompressed)
    if match:
        print(f"[!] Tìm thấy Flag trực tiếp: {match.group().decode()}")
        return

    # 4. Nếu vẫn không thấy, trích xuất Base64 (vì bạn thấy chuỗi {reb_C1...)
    # Thử khôi phục file bằng cách lấy mọi byte thứ 3, bỏ qua filter byte của Width=232
    width = 232
    row_size = 1 + (width * 3)
    recovered = bytearray()
    for i in range(0, len(decompressed), row_size):
        row = decompressed[i:i+row_size]
        if len(row) > 1:
            recovered.extend(row[1::3]) # Lấy từ byte thứ 2 (bỏ filter) và nhảy 3

    if b'0xfun{' in recovered:
        f_idx = recovered.find(b'0xfun{')
        f_end = recovered.find(b'}', f_idx) + 1
        print(f"[!] FLAG TÌM THẤY TRONG ARCHIVE: {recovered[f_idx:f_end].decode()}")
    else:
        # Ghi ra file để bạn tự kiểm tra strings lần cuối
        with open('final_check.dat', 'wb') as f:
            f.write(recovered)
        print("[*] Không thấy flag ngay, đã tạo file 'final_check.dat'.")
        print("[*] Hãy thử lệnh: strings final_check.dat | grep '0xfun'")

final_hunt('pixel.fun')