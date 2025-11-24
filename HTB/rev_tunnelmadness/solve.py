import struct
from collections import deque

# Các hằng số dựa trên phân tích
MAZE_DIM = 20  # Kích thước mỗi chiều của mê cung là 20
CELL_SIZE = 16 # Mỗi ô dữ liệu chiếm 16 bytes
CELL_TYPE_OFFSET = 12 # Loại ô (wall, path, end) nằm ở offset 12 trong 16 byte

# Hàm để lấy loại của một ô tại tọa độ (x, y, z)
def get_cell_type(maze_data, x, y, z):
    # Tính toán offset trong file maze.dat
    # Công thức giống hệt trong hàm get_cell của Ghidra
    offset = (x * MAZE_DIM * MAZE_DIM + y * MAZE_DIM + z) * CELL_SIZE
    
    # Lấy 4 byte tại vị trí offset + 12 để xác định loại ô
    type_bytes = maze_data[offset + CELL_TYPE_OFFSET : offset + CELL_TYPE_OFFSET + 4]
    
    # Giải nén 4 byte này thành một số nguyên (little-endian integer)
    cell_type = struct.unpack('<i', type_bytes)[0]
    return cell_type

# Hàm tìm đường đi bằng thuật toán BFS
def solve_maze(maze_data):
    # Hàng đợi cho BFS, mỗi phần tử là (tọa độ, đường đi hiện tại)
    queue = deque([((0, 0, 0), "")])
    
    # Set để lưu các ô đã đi qua, tránh lặp lại
    visited = set([(0, 0, 0)])
    
    # Định nghĩa các hướng di chuyển
    # (dx, dy, dz, ký tự)
    # L: Left, R: Right, B: Back, F: Forward, D: Down, U: Up
    directions = {
        'R': (1, 0, 0),
        'L': (-1, 0, 0),
        'F': (0, 1, 0),
        'B': (0, -1, 0),
        'U': (0, 0, 1),
        'D': (0, 0, -1)
    }
    
    while queue:
        (x, y, z), path = queue.popleft()
        
        # Kiểm tra nếu đã đến đích (ô có type == 3)
        if get_cell_type(maze_data, x, y, z) == 3:
            print("[+] Found the end point!")
            print(f"[+] Final coordinates: ({x}, {y}, {z})")
            return path
        
        # Thử di chuyển theo 6 hướng
        for move, (dx, dy, dz) in directions.items():
            nx, ny, nz = x + dx, y + dy, z + dz
            
            # Kiểm tra xem tọa độ mới có hợp lệ không
            if 0 <= nx < MAZE_DIM and 0 <= ny < MAZE_DIM and 0 <= nz < MAZE_DIM:
                # Kiểm tra nếu chưa đi qua ô này
                if (nx, ny, nz) not in visited:
                    # Kiểm tra ô này có phải là tường không (type == 2)
                    if get_cell_type(maze_data, nx, ny, nz) != 2:
                        visited.add((nx, ny, nz))
                        queue.append(((nx, ny, nz), path + move))
                        
    return None # Không tìm thấy đường đi

# --- Main execution ---
if __name__ == "__main__":
    try:
        with open("maze.dat", "rb") as f:
            maze_data = f.read()
            print(f"[*] Loaded maze.dat ({len(maze_data)} bytes)")
    except FileNotFoundError:
        print("[!] Error: maze.dat not found. Make sure you exported it from Ghidra.")
        exit(1)
        
    print("[*] Starting maze solver using BFS...")
    solution_path = solve_maze(maze_data)
    
    if solution_path:
        print("\n[SUCCESS] Path found. Copy the line below and paste it into the program:\n")
        print(solution_path)
    else:
        print("\n[FAIL] Could not find a path to the exit.")