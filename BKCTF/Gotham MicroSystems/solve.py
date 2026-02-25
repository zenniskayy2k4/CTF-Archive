from pwn import *
import binascii

def solve():
    # Chỉ mở DUY NHẤT một kết nối cho toàn bộ quá trình
    r = remote('gotham-microsystems-87f74e44fbb1e717.instancer.batmans.kitchen', 1337, ssl=True)
    
    # 1. Lấy Ciphertext từ câu chào mừng
    welcome = r.recvuntil(b"> ").decode()
    enc_hex = welcome.split("(")[1].split(")")[0]
    enc_bytes = binascii.unhexlify(enc_hex)
    blocks = [enc_bytes[i:i+16] for i in range(0, len(enc_bytes), 16)]
    
    full_plaintext = b""
    
    # 2. Giải mã từng block (Bỏ qua block 0 vì là Salt/IV)
    for k in range(1, len(blocks)):
        prev_block = blocks[k-1]
        target_block = blocks[k]
        dec_intermediate = [0] * 16
        
        log.info(f"Đang giải mã Block {k}...")
        
        for i in range(15, -1, -1):
            padding_val = 16 - i
            
            # Chuẩn bị 256 payloads cho 256 trường hợp của byte thứ i
            payload_list = []
            for cand in range(256):
                fake_prev = bytearray(16)
                # Set các byte đã biết phía sau để tạo đúng padding mong muốn
                for j in range(i + 1, 16):
                    fake_prev[j] = dec_intermediate[j] ^ padding_val
                fake_prev[i] = cand
                payload_list.append(binascii.hexlify(fake_prev + target_block))
            
            # GỬI TOÀN BỘ 256 payloads lên server trong một lần gửi duy nhất
            r.sendline(b"\n".join(payload_list))
            
            found_cand = -1
            # Đọc 256 phản hồi từ server
            for cand in range(256):
                # Mỗi payload gửi lên sẽ nhận về 1 dòng kết quả và 1 dòng prompt "> "
                res = r.recvline()
                r.recvuntil(b"> ") # Đọc bỏ dòng prompt tiếp theo
                
                # Nếu server không báo "Bad Padding", nghĩa là padding đã đúng
                if b"Bad Padding" not in res:
                    found_cand = cand
                    # Vì đã tìm thấy, ta cần đọc hết các response còn dư trong buffer của các candidate phía sau
                    for _ in range(255 - cand):
                        r.recvline()
                        r.recvuntil(b"> ")
                    break
            
            if found_cand != -1:
                dec_intermediate[i] = found_cand ^ padding_val
                # In progress để bạn theo dõi
                current_byte = dec_intermediate[i] ^ prev_block[i]
                print(f"Block {k} | Byte {i:02}: {hex(current_byte)} ('{chr(current_byte) if 32 <= current_byte <= 126 else '?'}')")
            else:
                log.error(f"Thất bại tại Block {k}, Byte {i}. Hãy kiểm tra lại kết nối.")
                return

        # Tính Plaintext của block sau khi tìm được toàn bộ intermediate state
        block_pt = bytes([dec_intermediate[j] ^ prev_block[j] for j in range(16)])
        full_plaintext += block_pt
        log.success(f"Kết quả Block {k}: {block_pt}")

    print(f"\n[!!!] FLAG CUỐI CÙNG: {full_plaintext.decode(errors='ignore')}")
    r.close()

if __name__ == "__main__":
    solve()