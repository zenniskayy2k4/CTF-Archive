from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor

# Kết nối
HOST = 'chall.lac.tf'
PORT = 31182

def get_ks(key, iv):
    # Keystream của AES-CTR (16 bytes đầu tiên)
    return AES.new(key, AES.MODE_CTR, nonce=iv).encrypt(b'\x00' * 16)

def solve():
    # p = process(['python3', 'server.py']) # Test local
    p = remote(HOST, PORT)

    # Bước 1: Chọn '0' để lấy dữ liệu cơ sở
    p.sendlineafter(b"decide your fate: ", b"0")

    # Bước 2: Parse nhãn wire 0 và 1
    # Format: wire 0: <hex> <ptr>
    p.recvuntil(b"wire 0: ")
    l0_raw = p.recvline().decode().strip().split()
    la0_key, pa = bytes.fromhex(l0_raw[0]), int(l0_raw[1])
    
    p.recvuntil(b"wire 1: ")
    l1_raw = p.recvline().decode().strip().split()
    lb0_key, pb = bytes.fromhex(l1_raw[0]), int(l1_raw[1])

    # Bước 3: Parse 3 dòng table
    # Format: <hex> <out_ptr>
    rows = {}
    # Các dòng này tương ứng với các cặp pointer (ptr_a, ptr_b) khác (0,0)
    # Thứ tự mặc định của product(range(2)) là (0,0), (0,1), (1,0), (1,1)
    # Vì (0,0) bị ẩn (GRR), 3 dòng nhận được là (0,1), (1,0), (1,1)
    table_indices = [(0, 1), (1, 0), (1, 1)]
    for i, j in table_indices:
        line = p.recvline().decode().strip().split()
        rows[(i, j)] = (bytes.fromhex(line[0]), int(line[1]))

    # Bước 4: Parse IV
    p.recvuntil(b"iv: ")
    iv = bytes.fromhex(p.recvline().decode().strip())

    log.info(f"IV: {iv.hex()}")
    log.info(f"Wire 0 (Server): Key={la0_key.hex()} Ptr={pa}")
    log.info(f"Wire 1 (User):   Key={lb0_key.hex()} Ptr={pb}")

    # Bước 5: Tính toán Keystream đã biết
    ka0 = get_ks(la0_key, iv)
    kb0 = get_ks(lb0_key, iv)

    # Bước 6: Tìm nhãn logic 0 (Lc0)
    # Input logic (0,0) luôn cho kết quả 0. Cặp pointer tương ứng là (pa, pb).
    if (pa, pb) == (0, 0):
        lc0 = strxor(ka0, kb0) # Dòng ẩn trong GRR
    else:
        row_ct, _ = rows[(pa, pb)]
        lc0 = strxor(strxor(row_ct, ka0), kb0)

    log.info(f"Nhãn logic 0 tìm được: {lc0.hex()}")

    # Bước 7: Khôi phục Keystream cho logic 1 (ka1, kb1)
    # Ta dùng các dòng mà kết quả AND vẫn là 0 (AND(0,1) và AND(1,0))
    # ptr_a=pa, ptr_b=1-pb (Logic 0,1 hoặc 1,0 tùy color bit) -> Kết quả vẫn là Lc0
    p_flip_b = (pa, 1 - pb)
    if p_flip_b == (0, 0):
        kb1_ks = strxor(lc0, ka0)
    else:
        kb1_ks = strxor(strxor(rows[p_flip_b][0], lc0), ka0)

    p_flip_a = (1 - pa, pb)
    if p_flip_a == (0, 0):
        ka1_ks = strxor(lc0, kb0)
    else:
        ka1_ks = strxor(strxor(rows[p_flip_a][0], lc0), kb0)

    # Bước 8: Tìm nhãn logic 1 (Lc1) - Đỉnh núi!
    # Logic (1,1) -> Kết quả logic 1. Cặp pointer là (1-pa, 1-pb)
    p11 = (1 - pa, 1 - pb)
    if p11 == (0, 0):
        lc1 = strxor(ka1_ks, kb1_ks)
    else:
        # Nhãn logic 1 nằm trong dòng cuối cùng của bảng chân lý
        row_ct, _ = rows[p11]
        lc1 = strxor(strxor(row_ct, ka1_ks), kb1_ks)

    log.success(f"Nhãn logic 1 (Hòn đá trên đỉnh): {lc1.hex()}")

    # Gửi nhãn "One" để lấy Flag
    p.sendlineafter(b"mountain: ", lc1.hex().encode())
    p.interactive()

if __name__ == "__main__":
    solve()