import struct

# --- Các hằng số và hàm cơ bản của SHA-256 ---
INITIAL_H_VALUES = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
]

K_CONSTANTS = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

def rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

def shr(x, n):
    return (x >> n) & 0xFFFFFFFF

def Ch(x, y, z):
    return (x & y) ^ (~x & z)

def Maj(x, y, z):
    return (x & y) ^ (x & z) ^ (y & z)

def Sigma0(x):
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)

def Sigma1(x):
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)

def sigma0(x):
    return rotr(x, 7) ^ rotr(x, 18) ^ shr(x, 3)

def sigma1(x):
    return rotr(x, 17) ^ rotr(x, 19) ^ shr(x, 10)

def _process_block(block_bytes, current_h_state):
    # block_bytes phải là 64 bytes
    assert len(block_bytes) == 64

    w = [0] * 64
    for i in range(16):
        w[i] = struct.unpack('>I', block_bytes[i*4:i*4+4])[0]

    for i in range(16, 64):
        s0 = sigma0(w[i-15])
        s1 = sigma1(w[i-2])
        w[i] = (w[i-16] + s0 + w[i-7] + s1) & 0xFFFFFFFF

    a, b, c, d, e, f, g, h = current_h_state

    for i in range(64):
        S1 = Sigma1(e)
        ch = Ch(e, f, g)
        temp1 = (h + S1 + ch + K_CONSTANTS[i] + w[i]) & 0xFFFFFFFF
        S0 = Sigma0(a)
        maj = Maj(a, b, c)
        temp2 = (S0 + maj) & 0xFFFFFFFF

        h = g
        g = f
        f = e
        e = (d + temp1) & 0xFFFFFFFF
        d = c
        c = b
        b = a
        a = (temp1 + temp2) & 0xFFFFFFFF

    new_h_state = [0] * 8
    new_h_state[0] = (current_h_state[0] + a) & 0xFFFFFFFF
    new_h_state[1] = (current_h_state[1] + b) & 0xFFFFFFFF
    new_h_state[2] = (current_h_state[2] + c) & 0xFFFFFFFF
    new_h_state[3] = (current_h_state[3] + d) & 0xFFFFFFFF
    new_h_state[4] = (current_h_state[4] + e) & 0xFFFFFFFF
    new_h_state[5] = (current_h_state[5] + f) & 0xFFFFFFFF
    new_h_state[6] = (current_h_state[6] + g) & 0xFFFFFFFF
    new_h_state[7] = (current_h_state[7] + h) & 0xFFFFFFFF
    
    return new_h_state

def sha256_custom_pad_and_hash(data_bytes, initial_h_state, total_processed_bits_before_data):
    """
    Hash data_bytes, bắt đầu với initial_h_state.
    total_processed_bits_before_data là số bit đã được xử lý *trước* khi data_bytes được thêm vào,
    để tính đúng padding cuối cùng.
    """
    current_h = list(initial_h_state) # Tạo bản copy để thay đổi
    
    message_len_bits = len(data_bytes) * 8
    
    # Padding cho data_bytes
    # Độ dài cuối cùng sẽ là total_processed_bits_before_data + message_len_bits
    final_total_bits = total_processed_bits_before_data + message_len_bits
    
    # Tạo message bao gồm data_bytes và padding của nó
    padded_data = bytearray(data_bytes)
    padded_data.append(0x80)
    
    # Số byte 0x00 cần thêm để len(padded_data) % 64 == 56
    # (len(data_bytes) + 1 + k) % 64 == 56
    # k = (56 - 1 - (len(data_bytes) % 64) + 64) % 64
    # Hoặc:
    num_zeros = (55 - len(data_bytes)) % 64 # Số byte 0 cần để kết thúc block hiện tại ở vị trí 56
                                          # hoặc để bắt đầu block mới và đến vị trí 56
    padded_data.extend(b'\x00' * num_zeros)
    
    # Thêm 8 byte độ dài (tổng độ dài bit của message gốc + data_bytes)
    padded_data.extend(struct.pack('>Q', final_total_bits)) # '>Q' for 64-bit big-endian

    assert len(padded_data) % 64 == 0

    # Xử lý từng block
    for i in range(0, len(padded_data), 64):
        block = bytes(padded_data[i:i+64]) # Chuyển bytearray slice thành bytes
        current_h = _process_block(block, current_h)
        
    return "".join(f"{val:08x}" for val in current_h)

# --- Logic Length Extension ---
def length_extension_sha256(original_hash_hex, secret_len_bytes, append_data_bytes):
    # 1. Khôi phục trạng thái hash từ original_hash_hex
    h_state_from_original_hash = [
        int(original_hash_hex[i*8 : (i+1)*8], 16) for i in range(8)
    ]

    # 2. Tính toán padding P cho message bí mật S (độ dài secret_len_bytes)
    #    để xác định L_S_padded (tổng số bit đã xử lý cho đến hết S_padded)
    #    L_S_padded sẽ là (secret_len_bytes + len(P)) * 8
    
    #    Message S || P (S_padded) được chia thành các block 64 byte.
    #    Padding P bao gồm 0x80, các 0x00, và 8 byte độ dài gốc của S (secret_len_bytes * 8).
    #    Độ dài của S_padded là bội của 64.
    
    #    Ví dụ: secret_len_bytes = 51
    #    S (51B) + 0x80 (1B) = 52B
    #    Cần k=4 byte 0x00 để 51+1+4 = 56.
    #    P = 0x80 || 0x00*4 || (51*8)_as_8_bytes
    #    len(P) = 1 + 4 + 8 = 13 bytes
    #    L_S_padded_bytes = secret_len_bytes + len(P) = 51 + 13 = 64 bytes.
    #    L_S_padded_bits = 64 * 8 = 512 bits.
    
    #    Tổng quát:
    #    Số byte 0x00 trong P là k = (55 - secret_len_bytes) % 64
    #    len_P_bytes = 1 (0x80) + k (0x00s) + 8 (length)
    #    L_S_padded_bytes = secret_len_bytes + len_P_bytes
    #    Tuy nhiên, L_S_padded_bytes phải là bội của 64.
    #    Cách tính đơn giản hơn:
    message_s_plus_padding_byte = secret_len_bytes + 1 # S + 0x80
    blocks_for_s_padded = (message_s_plus_padding_byte + 8 + 63) // 64 # Số block 64B sau khi S được pad hoàn chỉnh
                                                                        # (+8 là cho phần độ dài, +63//64 là làm tròn lên)
    L_S_padded_bytes_total = blocks_for_s_padded * 64
    
    # Cách tính L_S_padded_bytes_total (độ dài của S sau khi đã được pad hoàn chỉnh):
    # Giả sử `S` có độ dài `secret_len_bytes`.
    # `S` + `0x80`
    # Thêm `k` byte `0x00` sao cho `secret_len_bytes + 1 + k = 64*N - 8` (tức là `mod 64 = 56`)
    # `k = (56 - (secret_len_bytes + 1 % 64) + 64) % 64`
    # (Nếu `secret_len_bytes + 1 % 64` là `X`, thì `k = (55-X+64)%64`)
    # Hoặc, `k = ( (64 - 9 - (secret_len_bytes % 64)) % 64 )`
    # Sau đó thêm 8 byte độ dài.
    # Tổng độ dài của S đã pad:
    temp_len = secret_len_bytes + 1 # Độ dài S + 0x80
    num_zeros_for_S_padding = (55 - secret_len_bytes) % 64 # Số byte 00 trong block cuối của S (trước length)
                                                           # Đúng nếu temp_len <= 56 (tức secret_len_bytes <= 55)
                                                           # Nếu secret_len_bytes > 55, cần điều chỉnh
    if secret_len_bytes > 55: # Cần nhiều hơn 1 block để pad S
        # Ví dụ secret_len_bytes = 60.
        # S(60) + 0x80(1) = 61. Cần 3 byte 0x00 để hết block 1 (64B).
        # Sau đó cần 1 block nữa, trong đó 56 byte đầu là 0x00, rồi mới đến 8 byte độ dài.
        # k = num_zeros_to_fill_current_block + num_zeros_in_next_block_before_len
        # k = (64 - (secret_len_bytes + 1)%64)%64 + 56 (nếu (secret_len_bytes+1)%64 != 0)
        # Đây là phần phức tạp của padding nếu message dài.
        # Cách đơn giản: độ dài message sau khi thêm 0x80 và các 0x00 phải là X sao cho X % 64 == 56
        # rồi cộng 8. Tổng phải là bội của 64.
        
        # Độ dài của (S + 0x80 + 0x00...00) sao cho tổng này % 64 == 56
        len_before_length_field = secret_len_bytes + 1 # S + 0x80
        len_before_length_field += (56 - len_before_length_field % 64 + 64) % 64
        
        L_S_padded_bytes_total = len_before_length_field + 8
    else: # secret_len_bytes <= 55
        L_S_padded_bytes_total = 64 # S sẽ được pad thành đúng 1 block
        
    # 3. Tổng số bit đã xử lý cho đến hết S_padded
    total_bits_processed_for_S_padded = L_S_padded_bytes_total * 8

    # 4. Hash append_data_bytes, bắt đầu với h_state_from_original_hash,
    #    và thông báo rằng total_bits_processed_for_S_padded bit đã được xử lý trước đó.
    final_hash_hex = sha256_custom_pad_and_hash(
        append_data_bytes,
        h_state_from_original_hash,
        total_bits_processed_for_S_padded
    )
    
    # Để kiểm chứng, chúng ta cũng cần tạo ra message đầy đủ mà hash này tương ứng:
    # S_unknown || P_for_S || append_data_bytes
    # Tính P_for_S:
    padding_for_S = bytearray()
    padding_for_S.append(0x80)
    # Số byte 0x00 cần thêm cho S:
    num_zeros_S = (55 - secret_len_bytes) % 64
    if secret_len_bytes > 55: # Cần tính lại phức tạp hơn một chút
        current_len_with_80 = secret_len_bytes + 1
        num_zeros_S = (56 - current_len_with_80 % 64 + 64) % 64
    
    padding_for_S.extend(b'\x00' * num_zeros_S)
    padding_for_S.extend(struct.pack('>Q', secret_len_bytes * 8))

    forged_message_bytes = b"A" * secret_len_bytes + bytes(padding_for_S) + append_data_bytes
    # Chú ý: b"A"*secret_len_bytes chỉ là placeholder cho message bí mật gốc.

    return final_hash_hex, forged_message_bytes


# --- Phần code giải CTF sử dụng logic trên ---
import socket

HOST = 'vm.daotao.antoanso.org'
PORT = 34592
# HOST = '127.0.0.1' # Test local
# PORT = 10101      # Test local

def recv_line_strip(s):
    # Hàm tiện ích để đọc một dòng và strip()
    # Cẩn thận với việc server có thể không gửi '\n' ở cuối một số thông điệp
    # Hoặc gửi nhiều dòng một lúc.
    # Cách an toàn hơn là đọc đến một delimiter cụ thể nếu biết, hoặc đọc theo packet.
    # Tạm thời dùng recv lớn và splitlines.
    try:
        data = s.recv(2048) # Đọc một lượng lớn dữ liệu
        if not data:
            return "" # Server đóng kết nối
        lines = data.decode('utf-8', errors='replace').splitlines()
        # print(f"DEBUG recv: {lines}") # Để debug
        return lines # Trả về list các dòng
    except socket.timeout:
        print("Socket timeout while receiving.")
        return [""] # Trả về list có 1 chuỗi rỗng để tránh lỗi index
    except Exception as e:
        print(f"Error receiving data: {e}")
        return [""]

def solve():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((HOST, PORT))
            s.settimeout(10) # Đặt timeout
        except Exception as e:
            print(f"Không thể kết nối đến server: {e}")
            return

        lines = recv_line_strip(s) # WELCOME, Your task
        for line in lines: print(line)

        # Server sẽ gửi Flag length, Salt, rồi mới prompt "Tell me your name"
        # Chúng ta cần gửi response cho prompt đó
        
        # Đọc tiếp để lấy Flag length và Salt
        # Server có thể gửi chúng trong các packet riêng hoặc chung với prompt
        # Cần một logic đọc linh hoạt hơn
        
        flag_length = -1
        salt_from_server = ""
        original_hash_hex = ""
        
        # Vòng lặp đọc và xử lý output server
        buffer = ""
        got_name_prompt = False
        sent_username = False
        
        while True:
            try:
                data_chunk = s.recv(1024)
                if not data_chunk:
                    print("Server disconnected.")
                    break
                buffer += data_chunk.decode('utf-8', errors='replace')
            except socket.timeout:
                if not buffer and not got_name_prompt: # Nếu chưa nhận gì và timeout thì có thể server chưa gửi
                    print("Timeout waiting for initial server messages.")
                    break 
                # Nếu có buffer hoặc đã qua prompt thì xử lý buffer rồi break
                pass # Xử lý buffer bên dưới
            except Exception as e:
                print(f"Error receiving: {e}")
                break

            # Xử lý buffer
            while '\n' in buffer:
                line, buffer = buffer.split('\n', 1)
                line = line.strip()
                print(f"SERVER: {line}")

                if "Flag length:" in line:
                    flag_length = int(line.split("Flag length:")[1].strip())
                elif "Salt:" in line:
                    salt_from_server = line.split("Salt:", 1)[1].strip() # Strip ở đây có thể loại bỏ space cuối của salt
                                                                        # Cần lấy salt gốc
                    salt_from_server = line.split("Salt:", 1)[1] # Lấy cả phần sau "Salt: "
                    if salt_from_server.startswith(" "): salt_from_server = salt_from_server[1:] # Loại bỏ space đầu nếu có
                    # Không strip space cuối vì nó có thể là một phần của salt

                elif "Tell me your name:" in line and not sent_username:
                    got_name_prompt = True
                    username = "admin" 
                    print(f"CLIENT: Sending username: {username}")
                    s.sendall(username.encode() + b"\n")
                    sent_username = True
                elif "Message 1 hexdigest:" in line:
                    original_hash_hex = line.split("Message 1 hexdigest:")[1].strip()
                elif "Send hexdigest of message 2." in line:
                    # Đến lúc tính toán và gửi
                    if flag_length == -1 or not salt_from_server or not original_hash_hex:
                        print("Lỗi: Thiếu thông tin (flag_length, salt, hoặc original_hash) để tấn công.")
                        return

                    len_message_1 = len(username) + 1 + flag_length
                    data_to_append = salt_from_server.encode('utf-8') # Encoding salt gốc

                    print(f"\nThông tin cho Length Extension Attack:")
                    print(f"  Original hash (hash_m1): {original_hash_hex}")
                    print(f"  Original length (secret_len_bytes): {len_message_1} bytes")
                    print(f"  Data to append (salt): {data_to_append!r} (dài {len(data_to_append)} bytes)")
                    
                    new_digest, _ = length_extension_sha256(
                        original_hash_hex,
                        len_message_1,
                        data_to_append
                    )
                    print(f"  Calculated new digest (for message_2): {new_digest}")
                    print(f"CLIENT: Sending new digest: {new_digest}")
                    s.sendall(new_digest.encode() + b"\n")
                    
                    # Chờ phản hồi cuối cùng
                    final_response_buffer = ""
                    try:
                        while True: # Đọc đến khi server đóng hoặc timeout hoàn toàn
                            final_chunk = s.recv(1024)
                            if not final_chunk: break
                            final_response_buffer += final_chunk.decode('utf-8', errors='replace')
                    except socket.timeout:
                        pass # Timeout là bình thường nếu server không gửi gì thêm
                    
                    print("\nSERVER FINAL RESPONSE:")
                    for final_line in final_response_buffer.splitlines():
                        print(final_line.strip())
                        if "0160ca14" in final_line or "{" in final_line and "}" in final_line : # Heuristic tìm flag
                             print(f"FLAG POTENTIAL: {final_line.strip()}")
                    return # Kết thúc solve()

            if not data_chunk and not buffer : # Nếu recv trả về rỗng và buffer cũng rỗng, không còn gì để đọc
                 break
            if not got_name_prompt and not data_chunk: # Nếu chưa tới prompt tên mà server ngắt thì thoát
                 break


if __name__ == "__main__":
    solve()