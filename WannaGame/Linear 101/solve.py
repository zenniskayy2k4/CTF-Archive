from pwn import *
import random
import ast

HOST = 'challenge.cnsc.com.vn'
PORT = 30266

random.seed("Wanna Win?")
n = 128

def solve_crypto():
    p = remote(HOST, PORT)

    for round_num in range(64):
        log.info(f"--- Round {round_num + 1}/64 ---")
        
        # 2. Sinh lại ma trận A y hệt như server làm
        # Lưu ý: random.randbytes trả về bytes, truy cập A[i][j] sẽ ra số int
        A = [random.randbytes(n) for _ in range(n)]
        
        # 3. Nhận giá trị b từ server
        p.recvuntil(b'b = ')
        b_str = p.recvline().strip().decode()
        
        # Chuyển string '[...]' thành list
        b = ast.literal_eval(b_str)
        
        # 4. Tính toán x dựa trên công thức Max-Plus: x[j] = min(b[i] - A[i][j])
        x_candidate = []
        for j in range(n):
            # Tìm giá trị x[j] lớn nhất thỏa mãn ràng buộc của tất cả các hàng
            min_val = 255 # Giới hạn max của 1 byte là 255
            
            for i in range(n):
                diff = b[i] - A[i][j]
                if diff < min_val:
                    min_val = diff
            
            # min_val không được phép âm (về lý thuyết bài này sẽ không âm)
            if min_val < 0:
                min_val = 0
            
            x_candidate.append(min_val)
        
        # Chuyển list số nguyên thành bytes rồi sang hex để gửi
        sol_bytes = bytes(x_candidate)
        sol_hex = sol_bytes.hex()
        
        # 5. Gửi đáp án
        p.sendlineafter(b'x = ', sol_hex.encode())
        
        # Kiểm tra phản hồi (nếu sai sẽ bị ngắt kết nối hoặc in Wrong)
        # p.recvline() # Có thể dùng để debug

    # Sau 64 vòng lặp, nhận flag
    print(p.recvall().decode())

if __name__ == "__main__":
    solve_crypto()