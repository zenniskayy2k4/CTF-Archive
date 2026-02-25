from PIL import Image
import numpy as np
import itertools
import cv2
from pyzbar.pyzbar import decode

IMG = "chall.png"

def load_tiles():
    im = Image.open(IMG).convert("L")

    # ảnh là 450x450 (theo chall.py), co về 45x45 để đúng module
    im45 = im.resize((45, 45), Image.Resampling.NEAREST)
    a = np.array(im45, dtype=np.uint8)

    # binarize chắc chắn về 0/255
    a = (a > 127).astype(np.uint8) * 255

    tiles = []
    for ty in range(5):
        for tx in range(5):
            t = a[ty*9:(ty+1)*9, tx*9:(tx+1)*9].copy()
            tiles.append(t)
    return tiles

def edges(tile):
    # trả về (top, bottom, left, right) dưới dạng vector
    top = tile[0, :]
    bot = tile[-1, :]
    lef = tile[:, 0]
    rig = tile[:, -1]
    return top, bot, lef, rig

def edge_cost(e1, e2):
    # cost = số pixel khác nhau dọc biên
    return int(np.sum(e1 != e2))

def assemble_greedy(tiles):
    # precompute edges
    E = [edges(t) for t in tiles]
    n = len(tiles)

    # precompute pairwise costs for adjacency
    # right(i)->left(j), bottom(i)->top(j)
    cost_rl = np.zeros((n, n), dtype=int)
    cost_bt = np.zeros((n, n), dtype=int)
    for i in range(n):
        for j in range(n):
            if i == j: 
                cost_rl[i, j] = 10**9
                cost_bt[i, j] = 10**9
            else:
                cost_rl[i, j] = edge_cost(E[i][3], E[j][2])
                cost_bt[i, j] = edge_cost(E[i][1], E[j][0])

    # Ta giải bằng tìm kiếm có cắt tỉa (backtracking) vì 25 mảnh.
    # Dùng heuristic: đặt theo từng ô, chọn mảnh tốt nhất theo ràng buộc biên hiện có.
    best_grid = None
    best_score = 10**18

    order = [(r, c) for r in range(5) for c in range(5)]

    def backtrack(pos, used, grid, score):
        nonlocal best_grid, best_score
        if score >= best_score:
            return
        if pos == 25:
            best_grid = grid.copy()
            best_score = score
            return

        r, c = order[pos]

        # ràng buộc từ trái và trên (nếu có)
        left_tile = grid[r][c-1] if c > 0 else None
        top_tile  = grid[r-1][c] if r > 0 else None

        # tạo danh sách ứng viên và xếp theo cost tăng dần để cắt tỉa tốt
        cand = []
        for t in range(n):
            if t in used:
                continue
            add = 0
            if left_tile is not None:
                add += cost_rl[left_tile, t]
            if top_tile is not None:
                add += cost_bt[top_tile, t]
            cand.append((add, t))
        cand.sort(key=lambda x: x[0])

        # thử một số ứng viên đầu để nhanh (thường đủ vì biên QR rất “cứng”)
        for add, t in cand[:200]:
            used.add(t)
            grid[r][c] = t
            backtrack(pos+1, used, grid, score+add)
            used.remove(t)
            grid[r][c] = None

    grid = [[None]*5 for _ in range(5)]
    backtrack(0, set(), grid, 0)
    return best_grid, best_score

def build_image_from_grid(tiles, grid):
    out = np.zeros((45, 45), dtype=np.uint8)
    for r in range(5):
        for c in range(5):
            t = tiles[grid[r][c]]
            out[r*9:(r+1)*9, c*9:(c+1)*9] = t
    return out

def decode_qr(arr45):
    # phóng to để decoder dễ đọc
    big = cv2.resize(arr45, (450, 450), interpolation=cv2.INTER_NEAREST)
    # pyzbar expects 8-bit image
    res = decode(big)
    return res[0].data.decode() if res else None

def main():
    tiles = load_tiles()
    grid, score = assemble_greedy(tiles)
    print("best score:", score)
    arr = build_image_from_grid(tiles, grid)

    msg = decode_qr(arr)
    if msg:
        print("decoded:", msg)
    else:
        Image.fromarray(arr).resize((450,450), Image.Resampling.NEAREST).save("recovered.png")
        print("Could not decode; saved recovered.png for inspection")

if __name__ == "__main__":
    main()
