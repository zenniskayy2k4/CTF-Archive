from pwn import *

def solve():
    # Kết nối đến server
    r = remote('y2k-time-capsule-d467193a2b16ab8a.instancer.batmans.kitchen', 1337, ssl=True)
    
    # 1. Nhận dữ liệu từ server
    r.recvuntil(b"The last 5 codes used were:\n")
    data = r.recvline().decode().strip()
    
    # Chuyển string "[1, 2, 3, 4, 5]" thành list số nguyên
    nums = eval(data)
    log.info(f"Đã nhận 5 số: {nums}")
    
    # 2. Giải toán tìm a và c
    # Công thức: x[n+1] = (a * x[n] + c) % M
    # Hệ phương trình:
    # (1) x2 = (a*x1 + c) % 1999
    # (2) x3 = (a*x2 + c) % 1999
    # => (x3 - x2) = a * (x2 - x1) % 1999
    
    M = 1999
    x1, x2, x3, x4, x5 = nums
    
    try:
        # Tìm a = (x3 - x2) * nghịch_đảo(x2 - x1) % M
        # Hàm pow(n, -1, M) tính nghịch đảo modulo (yêu cầu Python 3.8+)
        diff_x = (x2 - x1) % M
        diff_y = (x3 - x2) % M
        
        a = (diff_y * pow(diff_x, -1, M)) % M
        c = (x2 - a * x1) % M
        
        log.success(f"Tìm thấy tham số: a={a}, c={c}")
        
        # 3. Dự đoán 5 số tiếp theo
        predictions = []
        last_val = x5
        for _ in range(5):
            next_val = (a * last_val + c) % M
            predictions.append(str(next_val))
            last_val = next_val
            
        payload = ",".join(predictions)
        log.info(f"Gửi chuỗi dự đoán: {payload}")
        
        # 4. Gửi kết quả và lấy Flag
        r.sendlineafter(b"> ", payload.encode())
        
        # Nhận tất cả phản hồi còn lại (bao gồm Flag)
        response = r.recvall().decode()
        print(response)
        
    except ValueError:
        log.error("Không thể tìm nghịch đảo (có thể x2 == x1). Hãy chạy lại script!")
    except Exception as e:
        log.error(f"Lỗi: {e}")
    finally:
        r.close()

if __name__ == "__main__":
    solve()