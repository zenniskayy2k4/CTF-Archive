import networkx as nx

# 1. Định nghĩa bản đồ dựa trên kết quả GDB của bạn
# S = (0,0). Các ô '#' và '.' đều là đường đi.
# Wall tại (2,0) và (2,3).
valid_nodes = {
    (0,0), (1,0),        # Row 0 (2,0 is Wall)
    (0,1), (1,1), (2,1), (3,1), (4,1), # Row 1
    (0,2), (1,2), (2,2), (3,2), (4,2), # Row 2
    (0,3), (1,3),        (3,3), (4,3), (5,3), # Row 3 (2,3 is Wall)
    (0,4), (1,4), (2,4), (3,4), (4,4), (5,4)  # Row 4
}

# 2. Xây dựng đồ thị
G = nx.Graph()
deltas = {
    'w': (0, -1), 's': (0, 1),
    'a': (-1, 0), 'd': (1, 0)
}

for x, y in valid_nodes:
    G.add_node((x, y))
    # Kết nối với hàng xóm
    for move, (dx, dy) in deltas.items():
        nx_node = (x + dx, y + dy)
        if nx_node in valid_nodes:
            G.add_edge((x, y), nx_node, direction=move)

# 3. Tìm đường đi Hamiltonian (đi qua mọi node đúng 1 lần)
# Bắt đầu từ (0,0)
print("[*] Searching for Hamiltonian path from (0,0)...")

def find_path(curr, visited, path_str):
    if len(visited) == len(valid_nodes):
        return path_str # Tìm thấy!
    
    # Thử các hướng đi tiếp theo
    # Ưu tiên thứ tự nào cũng được, DFS sẽ vét hết
    neighbors = []
    for neighbor in G.neighbors(curr):
        if neighbor not in visited:
            # Lấy hướng đi (w/a/s/d)
            direction = G.edges[curr, neighbor]['direction']
            # Chỉnh lại hướng nếu edge ngược (nx lưu vô hướng)
            # Logic: nếu neighbor = curr + delta -> đúng hướng
            for d_char, (dx, dy) in deltas.items():
                if (curr[0] + dx, curr[1] + dy) == neighbor:
                    neighbors.append((neighbor, d_char))
                    break
    
    for next_node, move in neighbors:
        res = find_path(next_node, visited | {next_node}, path_str + move)
        if res: return res

    return None

solution = find_path((0, 0), {(0, 0)}, "")

if solution:
    print(f"\n[+] FOUND PATH (Len {len(solution)}):")
    print(solution)
    print(f"\n[+] Command to run:")
    print(f'echo -n "{solution}" | ./starless_c')
else:
    print("[-] No path found.")