import os

# Cấu hình dựa trên FreeRobux.py
MARKER = b'\xAA\xBB\xCC\xDD'
KEY_SIZE = 32
FILENAME_SIZE = 60
BLOB_SIZE = FILENAME_SIZE + KEY_SIZE + len(MARKER)

# Hàm XOR từ mã nguồn gốc
def xor_decrypt(data, key):
    if not key: return b''
    o = bytearray()
    kl = len(key)
    for i, b in enumerate(data):
        o.append(b ^ key[i % kl])
    return bytes(o)

def solve():
    print("[*] Đang đọc file memory dump...")
    try:
        with open("ransomware.DMP", "rb") as f:
            dump_data = f.read()
    except FileNotFoundError:
        print("[-] Không tìm thấy file ransomware.DMP")
        return

    # Tìm tất cả vị trí của marker
    offsets = []
    start = 0
    while True:
        index = dump_data.find(MARKER, start)
        if index == -1:
            break
        offsets.append(index)
        start = index + 1

    print(f"[*] Tìm thấy {len(offsets)} khóa tiềm năng trong bộ nhớ.")

    found_keys = {}

    # Trích xuất thông tin từ dump
    for offset in offsets:
        # Cấu trúc: [Filename (60)] [Key (32)] [Marker (4)]
        # Offset hiện tại là vị trí bắt đầu của Marker
        
        # Lấy Key (32 byte trước marker)
        key_start = offset - KEY_SIZE
        key = dump_data[key_start : offset]
        
        # Lấy Filename (60 byte trước key)
        fname_start = key_start - FILENAME_SIZE
        fname_bytes = dump_data[fname_start : key_start]
        
        # Làm sạch tên file (bỏ padding \x00)
        try:
            original_filename = fname_bytes.replace(b'\x00', b'').decode('utf-8')
            found_keys[original_filename] = key
            print(f"[+] Đã khôi phục Key cho file: {original_filename}")
        except:
            continue

    # Tiến hành giải mã
    encrypted_dir = "encrypted_files" 
    if not os.path.exists(encrypted_dir):
        print(f"[-] Không tìm thấy thư mục {encrypted_dir}")
        return

    print("\n[*] Bắt đầu giải mã...")
    for filename in os.listdir(encrypted_dir):
        if not filename.endswith(".enc"):
            continue
            
        # Tên file gốc (bỏ đuôi .enc)
        original_name = filename[:-4]
        
        if original_name in found_keys:
            key = found_keys[original_name]
            enc_path = os.path.join(encrypted_dir, filename)
            
            with open(enc_path, "rb") as f_in:
                ciphertext = f_in.read()
                
            plaintext = xor_decrypt(ciphertext, key)
            
            # Lưu file đã giải mã
            out_path = os.path.join(encrypted_dir, "DECRYPTED_" + original_name)
            with open(out_path, "wb") as f_out:
                f_out.write(plaintext)
            
            print(f"[SUCCESS] Đã giải mã: {filename} -> {out_path}")
        else:
            print(f"[FAIL] Không tìm thấy key trong RAM cho file: {filename}")

if __name__ == "__main__":
    solve()