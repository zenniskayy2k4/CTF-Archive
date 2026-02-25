import multiprocessing
import aes
from aes import AES
import re

# ====================================================================
# 1. Tối ưu hoá MixColumns bằng Bảng tra cứu (Monkey Patching)
# ====================================================================
# Thay vì gọi hàm gf_mult() hàng triệu lần, ta tính trước các kết quả 
# nhân với 2 và 3 trong trường GF(2^8) để tăng tốc script lên cực đại.
MUL2 = [0] * 256
MUL3 = [0] * 256
for x in range(256):
    m2 = (x << 1) & 0xFF
    if x & 0x80:
        m2 ^= 0x1B
    MUL2[x] = m2
    MUL3[x] = m2 ^ x

def fast_mix_columns(state):
    # state is expected to be a 4x4 matrix of ints (0..255) indexed as state[row][col]
    result = [[0] * 4 for _ in range(4)]
    for c in range(4):
        a0 = state[0][c]
        a1 = state[1][c]
        a2 = state[2][c]
        a3 = state[3][c]

        result[0][c] = MUL2[a0] ^ MUL3[a1] ^ a2 ^ a3
        result[1][c] = a0 ^ MUL2[a1] ^ MUL3[a2] ^ a3
        result[2][c] = a0 ^ a1 ^ MUL2[a2] ^ MUL3[a3]
        result[3][c] = MUL3[a0] ^ a1 ^ a2 ^ MUL2[a3]
    return result

# Ép class AES dùng hàm mix_columns siêu tốc của chúng ta
aes.mix_columns = fast_mix_columns


# ====================================================================
# 2. Hàm Worker chạy song song để brute-force 3 bytes cuối
# ====================================================================
def brute_force_worker(start_i):
    key_prefix = bytes.fromhex("26ab77cadcca0ed41b03c8f2e5")
    
    # Lấy cặp Plaintext-Ciphertext đầu tiên từ output.txt để kiểm chứng khóa
    pt = bytes.fromhex("376f73334dc9db2a4d20734c0783ac69")
    ct_expected = bytes.fromhex("9070f81f4de789663820e8924924732b")
    
    # Duyệt 2 bytes cuối (Byte đầu tiên chia cho nhân CPU xử lý)
    for j in range(256):
        for k in range(256):
            key = key_prefix + bytes([start_i, j, k])
            cipher = AES(key)
            if cipher.encrypt(pt) == ct_expected:
                return key
    return None


# ====================================================================
# 3. Hàm Main chạy Đa luồng và In Flag
# ====================================================================
if __name__ == '__main__':
    print(" Đang khởi động quá trình Brute-force 3 bytes cuối của khóa...")
    print(" Quá trình này tận dụng toàn bộ nhân CPU, vui lòng đợi 1-2 phút...\n")
    
    # Tạo pool xử lý tương đương số nhân CPU
    pool = multiprocessing.Pool(processes=multiprocessing.cpu_count())
    
    # Chia cho mỗi tiến trình xử lý vòng lặp đầu tiên (start_i từ 0 -> 255)
    for result in pool.imap_unordered(brute_force_worker, range(256)):
        if result is not None:
            print(f" BINGO! Đã tìm thấy Key gốc: {result.hex()}")
            pool.terminate() # Ngưng các luồng khác vì đã tìm ra key
            
            # Khởi tạo AES với khóa chính xác và giải mã mảng encrypted_flag
            cipher = AES(result)
            enc_flag = bytes.fromhex("8e70387dc377a09cbc721debe27c468157b027e3e63fe02560506f70b3c72ca19130ae59c6eef47b734bb0147424ec936fc91dc658d15dee0b69a2dc24a78c44")
            
            flag = b""
            # Giải mã từng khối 16 bytes (ECB Mode)
            for i in range(0, len(enc_flag), 16):
                block = enc_flag[i:i+16]
                flag += cipher.decrypt(block)
            
            # Xuất Flag bỏ qua các bytes padding (rác đệm)
            flag_str = flag.decode('utf-8', errors='ignore')
            
            # Lọc lấy chính xác format Flag
            match = re.search(r'BITSCTF\{.*?\}', flag_str)
            if match:
                print(f" CHÍNH XÁC FLAG LÀ: {match.group(0)}")
            else:
                print(f" Đoạn văn bản đã giải mã: {flag_str}")
            break