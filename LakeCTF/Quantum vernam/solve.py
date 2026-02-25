from pwn import *
import numpy as np

# Cấu hình kết nối
host = 'chall.polygl0ts.ch'
port = 6002

def solve():
    # Kết nối đến server
    r = remote(host, port)

    print("[-] Đang đọc ma trận X...")
    
    # 1. Đọc ma trận X
    # Đọc cho đến khi gặp chuỗi "matrix x ="
    r.recvuntil(b'matrix x = ')
    
    # Đọc tiếp cho đến khi hết ma trận (dấu đóng ngoặc vuông kép "]]")
    matrix_raw = r.recvuntil(b']]').decode()
    
    # Xử lý chuỗi: xóa dấu ngoặc [, ]
    matrix_clean = matrix_raw.replace('[', '').replace(']', '')
    
    # Tách chuỗi bằng khoảng trắng (tự động xử lý nhiều dấu cách hoặc xuống dòng)
    parts = matrix_clean.split()
    
    # Chuyển đổi sang số phức
    elements = [complex(p) for p in parts]
    
    # Tạo ma trận numpy 2x2
    x = np.array(elements).reshape(2, 2)
    print(f"[*] Đã nhận ma trận X:\n{x}")

    # 2. Tính toán Gate 1 và Gate 2
    # Tìm vector riêng (eigenvectors) của X
    # Khi mã hóa ở basis là vector riêng, ma trận X chỉ thêm vào một Global Phase, 
    # Global Phase không ảnh hưởng đến kết quả đo lường (|psi|^2).
    eigvals, eigvecs = np.linalg.eig(x)
    
    # Gate 1: Chuyển từ cơ sở tính toán sang cơ sở vector riêng
    gate1 = eigvecs
    
    # Gate 2: Chuyển ngược lại (Nghịch đảo của Gate 1)
    gate2 = np.linalg.inv(gate1)

    print("[*] Đã tính toán xong Gate 1 và Gate 2 (Eigenbasis strategy)")

    # 3. Gửi ma trận lên server
    def send_matrix(matrix):
        flat = matrix.flatten()
        for val in flat:
            # Đọc chờ dấu nhắc "element:" rồi gửi giá trị
            r.recvuntil(b':') 
            r.sendline(str(val).encode())

    print("[-] Đang gửi Gate 1...")
    send_matrix(gate1)
    
    print("[-] Đang gửi Gate 2...")
    send_matrix(gate2)

    # 4. Nhận Flag
    # Server trả về "measurement: [0, 1, ...]" sau đó là Flag
    r.recvuntil(b'measurement:')
    r.recvline() # Bỏ qua dòng chứa mảng bit
    
    flag = r.recvline().strip().decode()
    print(f"\n[+] FLAG: {flag}")
    
    r.close()

if __name__ == '__main__':
    solve()