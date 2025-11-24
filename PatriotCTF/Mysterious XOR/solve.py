import socket
import datetime
import time

HOST = '18.212.136.134'
PORT = 2345

def get_payload(timestamp_str):
    # 1. Tạo chuỗi filename: /tmp/YYYYMMDDTHHMMZ
    base_string = f"/tmp/{timestamp_str}"
    
    # 2. Key và padding
    key_prefix = "1337"
    padding_char = 0x20
    
    # 3. XOR
    payload = bytearray()
    for i in range(19): # Chuỗi dài 19 ký tự
        char_code = ord(base_string[i])
        
        if i < len(key_prefix):
            key_code = ord(key_prefix[i])
        else:
            key_code = padding_char
            
        payload.append(char_code ^ key_code)
    
    # Thêm ký tự \n (0x0a)
    payload.append(10)
    return payload

def attack():
    # Lấy giờ UTC hiện tại
    now = datetime.datetime.now(datetime.timezone.utc)
    
    # Format giống code C: YYYYMMDDTHHMMZ
    # Lưu ý: Code C lấy tm_year, tm_mon+1, tm_mday, tm_hour, tm_min. 
    # Python strftime làm chính xác điều này.
    ts_str = now.strftime("%Y%m%dT%H%MZ")
    
    print(f"[*] Current Time (UTC): {ts_str}")
    payload = get_payload(ts_str)
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((HOST, PORT))
        print(f"[*] Sending payload for time: {ts_str}")
        
        s.sendall(payload)
        
        response = s.recv(4096)
        print("\n[+] Server Response:")
        print(response.decode(errors='ignore'))
        s.close()
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    # Đôi khi đồng hồ server lệch một chút, nếu chạy lần 1 Failed, 
    # hãy thử chạy lại ngay lập tức hoặc chỉnh giờ máy tính chuẩn UTC.
    attack()