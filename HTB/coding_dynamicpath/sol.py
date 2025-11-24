#!/usr/bin/env python3
from pwn import *

# --- THÔNG TIN KẾT NỐI ---
HOST = "94.237.60.55"
PORT = 44607
# -------------------------

def solve_grid(rows, cols, numbers):
    """
    Hàm này triển khai thuật toán Dynamic Programming để tìm đường đi ngắn nhất.
    """
    grid = []
    # Chuyển đổi danh sách 1D thành lưới 2D
    for r in range(rows):
        row_data = numbers[r * cols : (r + 1) * cols]
        grid.append(row_data)

    # Xử lý hàng đầu tiên
    for c in range(1, cols):
        grid[0][c] += grid[0][c-1]

    # Xử lý cột đầu tiên
    for r in range(1, rows):
        grid[r][0] += grid[r-1][0]
        
    # Xử lý các ô còn lại
    for r in range(1, rows):
        for c in range(1, cols):
            grid[r][c] += min(grid[r-1][c], grid[r][c-1])
            
    # Kết quả là ô dưới cùng bên phải
    return grid[rows-1][cols-1]


def main():
    # Kết nối đến server
    conn = remote(HOST, PORT)
    
    # Bỏ qua phần giới thiệu ban đầu một cách an toàn
    conn.recvuntil(b"Example Response:\n")
    conn.recvline() # Đọc dòng '17'
    conn.recvline() # Đọc dòng trống
    conn.recvline() # Đọc dòng '(Optimal route...)'

    # Lặp qua 100 bài toán
    for i in range(100):
        try:
            # SỬA LỖI: Đọc cho đến khi gặp dòng "Test x/100"
            # Điều này giúp bỏ qua các dòng trống hoặc dòng lạ
            test_line = conn.recvuntil(b'Test ').strip()
            test_line += conn.recvline() # Đọc nốt phần còn lại của dòng Test
            print(test_line.decode().strip())

            # Đọc và xử lý dòng kích thước
            dims_line = conn.recvline().strip().decode()
            rows, cols = map(int, dims_line.split())
            
            # Đọc và xử lý dòng chứa các số
            nums_line = conn.recvline().strip().decode()
            numbers = list(map(int, nums_line.split()))

            # Đợi dấu nhắc '>'
            conn.recvuntil(b'> ')

            # Giải bài toán
            result = solve_grid(rows, cols, numbers)
            print(f"  -> Grid: {rows}x{cols}, Gửi kết quả: {result}")

            # Gửi kết quả lại cho server
            conn.sendline(str(result).encode())
        
        except (ValueError, IndexError, EOFError) as e:
            print(f"[*] Lỗi xảy ra hoặc kết nối đã đóng: {e}")
            break

    # Sau khi giải xong 100 bài, server có thể sẽ gửi flag
    print("\n[+] Đã giải xong. Đang chờ flag...")
    conn.interactive()


if __name__ == "__main__":
    main()