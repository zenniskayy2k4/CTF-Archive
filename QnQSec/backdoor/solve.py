import ctypes
import lief
import sys
from Crypto.Cipher import ChaCha20

# Hằng số từ file thực thi
SRAND_SEED = 0x1337
ENCRYPTED_FUNCTION_VA = 0x00108509  # Địa chỉ ảo của hàm bị mã hóa
ENCRYPTED_DATA_SIZE = 0x135         # Kích thước dữ liệu mã hóa (309 bytes)
CHACHA_INITIAL_COUNTER = 1          # Được đặt trong FUN_00107e88

def generate_key_and_nonce():
    """
    Tái tạo lại quá trình tạo key và nonce bằng cách gọi các hàm C từ libc.
    Điều này đảm bảo kết quả giống hệt với chương trình gốc.
    """
    try:
        # Tải thư viện C chuẩn của hệ thống
        libc = ctypes.CDLL(ctypes.util.find_library('c'))
    except (OSError, AttributeError):
        print("[LỖI] Không thể tìm thấy thư viện C (libc). Script này có thể cần chạy trên Linux.")
        sys.exit(1)

    # Đặt seed cho bộ sinh số ngẫu nhiên
    libc.srand(SRAND_SEED)

    # --- Tạo key (local_98) ---
    # for (local_c = 0; local_c < 0x20; local_c = local_c + 1) {
    #   iVar1 = rand();
    #   local_98[local_c] = (char)iVar1 * '\x02';
    # }
    key = bytearray()
    for _ in range(32): # 0x20 = 32
        rand_val = libc.rand()
        # Lấy byte thấp nhất, nhân 2, và lại lấy byte thấp nhất
        key_byte = ((rand_val & 0xFF) * 2) & 0xFF
        key.append(key_byte)
    
    # --- Tạo nonce (local_a4) ---
    # for (local_10 = 0; local_10 < 0xc; local_10 = local_10 + 1) {
    #   iVar1 = rand();
    #   local_a4[local_10] = (char)iVar1;
    # }
    nonce = bytearray()
    for _ in range(12): # 0xc = 12
        rand_val = libc.rand()
        nonce_byte = rand_val & 0xFF
        nonce.append(nonce_byte)

    print(f"[+] Đã tạo Key    (32 bytes): {bytes(key).hex()}")
    print(f"[+] Đã tạo Nonce   (12 bytes): {bytes(nonce).hex()}")
    
    return bytes(key), bytes(nonce)

def extract_encrypted_data(binary_path):
    """
    Trích xuất các byte bị mã hóa từ file ELF bằng thư viện lief.
    """
    print(f"[*] Đang đọc file: {binary_path}")
    binary = lief.parse(binary_path)
    if not binary:
        print(f"[LỖI] Không thể phân tích file: {binary_path}")
        sys.exit(1)
        
    try:
        # Lấy nội dung của section chứa địa chỉ ảo cần tìm
        # lief sẽ tự động chuyển đổi VA -> offset
        encrypted_bytes = bytes(binary.get_content_from_virtual_address(ENCRYPTED_FUNCTION_VA, ENCRYPTED_DATA_SIZE))
        print(f"[+] Đã trích xuất {len(encrypted_bytes)} bytes mã hóa từ địa chỉ 0x{ENCRYPTED_FUNCTION_VA:x}")
        return encrypted_bytes
    except lief.bad_address as e:
        print(f"[LỖI] Không tìm thấy địa chỉ 0x{ENCRYPTED_FUNCTION_VA:x} trong file. Địa chỉ có đúng không?")
        sys.exit(1)

def main():
    if len(sys.argv) != 2:
        print(f"Sử dụng: python {sys.argv[0]} <đường_dẫn_tới_file_thực_thi>")
        return

    binary_path = sys.argv[1]

    # Bước 1: Tái tạo key và nonce
    key, nonce = generate_key_and_nonce()

    # Bước 2: Trích xuất dữ liệu mã hóa
    ciphertext = extract_encrypted_data(binary_path)

    # Bước 3: Giải mã bằng ChaCha20
    cipher = ChaCha20.new(key=key, nonce=nonce)
    
    # ChaCha20 counter bắt đầu từ 1, không phải 0.
    # seek() để di chuyển keystream đến vị trí bắt đầu đúng
    # (vì cipher được khởi tạo với counter=0)
    cipher.seek(CHACHA_INITIAL_COUNTER * 64) 
    
    decrypted_data = cipher.decrypt(ciphertext)
    
    output_filename = "decrypted_bin.bin"
    with open(output_filename, "wb") as f:
        f.write(decrypted_data)
        
    print("-" * 50)
    print(f"[SUCCESS] Dữ liệu đã được giải mã và lưu vào file: '{output_filename}'")
    print("  Bây giờ bạn có thể mở file này bằng Ghidra hoặc hex editor để tìm các giá trị băm.")
    print("-" * 50)
    
    # In ra một phần dữ liệu để kiểm tra
    print("Hex dump của dữ liệu đã giải mã (32 bytes đầu tiên):")
    print(decrypted_data[:32].hex())


if __name__ == "__main__":
    main()