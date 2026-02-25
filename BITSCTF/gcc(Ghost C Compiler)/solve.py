import sys

def solve(file_path):
    with open(file_path, 'rb') as f:
        data = f.read()

    size = len(data)
    fnv_prime = 0x100000001b3
    offset_basis = 0xcbf29ce484222325
    mask = 0xffffffffffffffff

    print(f" Đang phân tích file {file_path} (Kích thước: {size} bytes)...")

    # Tính trước mã băm cho nửa đầu để tối ưu tốc độ duyệt
    fwd_hashes = [offset_basis] * (size + 1)
    for i in range(size):
        fwd_hashes[i + 1] = ((fwd_hashes[i] ^ data[i]) * fnv_prime) & mask

    # Thử tất cả các vị trí (offset) có thể là nơi chứa 64 byte flag
    for i in range(size - 63):
        h = fwd_hashes[i]
        
        # Băm tiếp nửa dữ liệu nằm sau 64 byte flag (bỏ qua đoạn từ i đến i+63)
        for j in range(i + 64, size):
            h = ((h ^ data[j]) * fnv_prime) & mask
            
        h ^= 0xcafebabe00000000
        
        # Thử giải mã 8 byte đầu tiên với key là mã băm h
        key = h
        decrypted = bytearray()
        for j in range(8):
            decrypted.append((key & 0xff) ^ data[i + j])
            # ROR 1 (Xoay dịch vòng phải 1 bit giống hàm mã hoá gốc)
            key = (key >> 1) | ((key & 1) << 63)
            
        # Kiểm tra Signature
        if decrypted == b"BITSCTF{":
            print(f" Đã tìm thấy vị trí flag bị mã hoá tại offset: 0x{i:x}")
            
            # Khớp cấu trúc, tiến hành giải mã toàn bộ 64 byte
            full_key = h
            flag = bytearray()
            for j in range(64):
                flag.append((full_key & 0xff) ^ data[i + j])
                full_key = (full_key >> 1) | ((full_key & 1) << 63)
                
            # Xoá các byte null (padding) ở cuối để chuỗi đẹp hơn
            final_flag = flag.decode('utf-8', 'ignore').strip('\x00')
            print(f" Flag: {final_flag}")
            return

    print(" Không tìm thấy flag.")
    print(" Lưu ý: Bạn cần dùng file 'ghost_compiler' nguyên gốc. Nếu file bị chạy thử, flag đã bị nó tự động xoá mất!")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Sử dụng: python {sys.argv[0]} <file_ghost_compiler>")
    else:
        solve(sys.argv[1])