#!/usr/bin/env python3

from pwn import *
from collections import deque
import numpy as np
from fractions import Fraction

# Hằng số từ server
limit = 0xe5db6a6d765b1ba6e727aa7a87a792c49bb9ddeb2bad999f5ea04f047255d5a72e193a7d58aa8ef619b0262de6d25651085842fd9c385fa4f1032c305f44b8a4f92b16c8115d0595cebfccc1c655ca20db597ff1f01e0db70b9073fbaa1ae5e489484c7a45c215ea02db3c77f1865e1e8597cb0b0af3241cd8214bd5b5c1491f

def part_to_matrix(part):
    e = [int.from_bytes(part[i:i+2], "big") for i in range(0, len(part), 2)]
    return np.array([[e[0], e[1]], [e[2], e[3]]], dtype=object)

def generate_forward_paths(start_pos, steps, max_depth):
    """
    Tiền tính toán: chạy BFS từ start_pos ra max_depth bước
    Lưu tất cả các điểm đến hợp lệ và đường đi vào dict.
    """
    print(f"    [*] Pre-computing forward paths up to depth {max_depth}...")
    fwd_paths = {start_pos: []}
    q = deque([(start_pos, [])])
    
    while q:
        current_pos, path_indices = q.popleft()
        
        if len(path_indices) >= max_depth:
            continue
            
        for i in range(len(steps)):
            if i in path_indices:
                continue
                
            next_pos_np = np.dot(steps[i]['matrix'], np.array(current_pos, dtype=object))
            next_pos = tuple(map(int, next_pos_np))
            
            if next_pos not in fwd_paths and next_pos[0] <= limit and next_pos[1] <= limit:
                new_path = path_indices + [i]
                fwd_paths[next_pos] = new_path
                q.append((next_pos, new_path))
                
    print(f"    [*] Forward pre-computation done. Found {len(fwd_paths)} reachable positions.")
    return fwd_paths

def solve_round(start_pos, final_pos, mind_hex):
    mind_bytes = bytes.fromhex(mind_hex)
    parts = [mind_bytes[i:i+8] for i in range(0, 1000, 8)]
    
    steps = []
    for part in parts:
        mat = part_to_matrix(part)
        a, b, c, d = mat[0, 0], mat[0, 1], mat[1, 0], mat[1, 1]
        det = a * d - b * c
        inv_mat = None
        if det != 0:
            inv_mat = np.array([[Fraction(d, det), Fraction(-b, det)], [Fraction(-c, det), Fraction(a, det)]], dtype=object)
        steps.append({'part': part, 'matrix': mat, 'inv_matrix': inv_mat})

    # Giai đoạn 1: Tiền tính toán các đường đi tiến
    fwd_paths = generate_forward_paths(start_pos, steps, max_depth=4)

    # Giai đoạn 2: Lặp tìm bước cuối và tìm kiếm lùi để gặp
    max_bwd_depth = 4
    for kx in range(40): # Tăng phạm vi một chút cho chắc chắn
        for ky in range(40):
            if kx == 0 and ky == 0: continue

            pos_final_unmodded = np.array([final_pos[0] + kx * limit, final_pos[1] + ky * limit], dtype=object)
            
            for last_step_idx in range(len(steps)):
                # Tìm kiếm lùi từ target_pos
                q_bwd = deque([(pos_final_unmodded, [last_step_idx])]) # (current_pos_frac, path_indices)

                while q_bwd:
                    current_pos_frac, bwd_path = q_bwd.popleft()
                    
                    # Kiểm tra xem có phải số nguyên không
                    x_frac, y_frac = current_pos_frac[0], current_pos_frac[1]
                    if x_frac.denominator != 1 or y_frac.denominator != 1:
                        continue
                    
                    current_pos_int = (int(x_frac), int(y_frac))

                    # Kiểm tra xem có gặp được điểm nào trong fwd_paths không
                    if current_pos_int in fwd_paths:
                        fwd_path = fwd_paths[current_pos_int]
                        # Kiểm tra xem các bước có bị trùng lặp không
                        if not (set(fwd_path) & set(bwd_path)):
                            print(f"    [+] Match found! Fwd path (len {len(fwd_path)}) meets Bwd path (len {len(bwd_path)}).")
                            # Đường đi lùi đang bị ngược, cần đảo lại
                            full_path_indices = fwd_path + bwd_path[::-1]
                            solution_bytes = b"".join(steps[j]['part'] for j in full_path_indices)
                            return solution_bytes.hex()
                    
                    # Nếu chưa gặp và chưa quá sâu, đi lùi tiếp
                    if len(bwd_path) < max_bwd_depth:
                        for prev_step_idx in range(len(steps)):
                            if prev_step_idx in bwd_path: continue
                            
                            inv_mat = steps[prev_step_idx]['inv_matrix']
                            if inv_mat is None: continue
                            
                            next_bwd_pos = np.dot(inv_mat, current_pos_frac)
                            q_bwd.append((next_bwd_pos, bwd_path + [prev_step_idx]))

    return None

# ---- Main script ----
HOST = "catch.chal.idek.team"
PORT = 1337

conn = remote(HOST, PORT)

for round_num in range(20):
    print(f"[*] Round {round_num + 1}/20")
    
    conn.recvuntil(b"Co-location: ")
    start_pos = eval(conn.recvline().strip().decode())

    conn.recvuntil(b"Cat's hidden mind: ")
    mind_hex = conn.recvline().strip().decode()

    conn.recvuntil(b"Cat now at: ")
    final_pos = eval(conn.recvline().strip().decode())
    
    solution_hex = solve_round(start_pos, final_pos, mind_hex)
    
    if solution_hex is None:
        print("[-] Failed to solve round.")
        conn.close()
        break

    conn.recvuntil(b" Path to recall (hex): ")
    conn.sendline(solution_hex.encode())
    
    response = conn.recvline()
    print(response.decode().strip())
    if b"Reunion!" not in response:
        print("[-] Server rejected the solution.")
        break

conn.interactive()