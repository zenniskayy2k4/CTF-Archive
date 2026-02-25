import gdb
import sys

# Tăng giới hạn đệ quy
sys.setrecursionlimit(5000)

print("\n" + "="*50)
print("[*] MULTI-PATH SOLVER STARTED")

# 1. QUÉT MEMORY
valid_nodes = set()
try:
    mappings = gdb.execute("info proc mappings", to_string=True).splitlines()
except:
    mappings = []

# Fallback scan nếu info proc fail
if not mappings:
    print("[!] 'info proc mappings' failed. Using fallback scanner...")
    inf = gdb.selected_inferior()
    try:
        base = int(gdb.parse_and_eval("$rip")) & 0xFFF00000
        for off in range(0, 0x500000, 0x1000):
            try:
                inf.read_memory(base + off, 1)
                valid_nodes.add(base + off)
            except: pass
            try:
                inf.read_memory(base - off, 1)
                valid_nodes.add(base - off)
            except: pass
    except: pass
else:
    for line in mappings:
        parts = line.split()
        if len(parts) >= 3:
            try:
                start = int(parts[0], 16)
                end = int(parts[1], 16)
                if (end - start) == 0x1000:
                    valid_nodes.add(start)
            except: pass

print(f"[*] Candidates found: {len(valid_nodes)} nodes")

# 2. XÂY DỰNG ĐỒ THỊ
deltas = { 'w': -0x8000, 's': 0x8000, 'a': -0x1000, 'd': 0x1000 }
adj = {node: [] for node in valid_nodes}
real_nodes = set()

for u in valid_nodes:
    has_neighbor = False
    for move, diff in deltas.items():
        v = u + diff
        if v in valid_nodes:
            adj[u].append((v, move))
            has_neighbor = True
    if has_neighbor:
        real_nodes.add(u)

nodes_list = sorted(list(real_nodes))
n_nodes = len(nodes_list)
print(f"[*] Graph built. Real Maze Nodes: {n_nodes}")

# 3. TÌM TẤT CẢ ĐƯỜNG ĐI
solutions = []

def backtrack(curr, path, visited_mask):
    # Nếu đã tìm đủ 5 giải pháp thì dừng để tiết kiệm thời gian
    if len(solutions) >= 5:
        return

    # Nếu đi hết tất cả các node
    if bin(visited_mask).count('1') == n_nodes:
        solutions.append(path)
        return
    
    # Ưu tiên thứ tự: Xuống (s), Phải (d), Trái (a), Lên (w)
    neighbors = adj.get(curr, [])
    neighbors.sort(key=lambda x: {'s':0, 'd':1, 'a':2, 'w':3}.get(x[1], 9))

    for neighbor, move in neighbors:
        try:
            idx = nodes_list.index(neighbor)
            if not (visited_mask & (1 << idx)):
                backtrack(neighbor, path + move, visited_mask | (1 << idx))
        except ValueError: pass

# Xác định Start Node (Dựa trên RIP hiện tại hoặc node thấp nhất)
start_candidates = []
try:
    rip = int(gdb.parse_and_eval("$rip"))
    # Tìm node chứa RIP
    for node in nodes_list:
        if node <= rip < node + 0x1000:
            start_candidates = [node]
            print(f"[*] Identified Start Node from RIP: {hex(node)}")
            break
except: pass

if not start_candidates:
    print("[!] Could not auto-detect Start. Trying all nodes...")
    start_candidates = nodes_list

print("[*] Brute-forcing paths...")
for start_node in start_candidates:
    try:
        s_idx = nodes_list.index(start_node)
        backtrack(start_node, "", (1 << s_idx))
    except: pass
    if len(solutions) >= 5: break

print("\n" + "#"*50)
if solutions:
    print(f"[+] FOUND {len(solutions)} POSSIBLE PATHS:")
    for i, sol in enumerate(solutions):
        print(f"Option {i+1}: {sol}")
    print("#"*50)
    print("Try Option 1 first. If it crashes or fails, try Option 2, etc.")
else:
    print("[-] No Hamiltonian path found. Check map connectivity.")