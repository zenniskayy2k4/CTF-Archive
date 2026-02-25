import os
import re

ROWS = 19
COLS = 101

def _read_text(path):
    with open(path, "r", encoding="utf-8") as f:
        return f.read()

def extract_flag_regex(filename="script.js"):
    here = os.path.dirname(os.path.abspath(__file__))
    content = _read_text(os.path.join(here, filename))
    m = re.search(r"const theFlag = /(.*)/;", content, re.DOTALL)
    if not m:
        raise ValueError("Không tìm thấy `const theFlag = /.../;` trong script.js")
    return m.group(1)

def parse_regex_constraints(filename="script.js"):
    regex_str = extract_flag_regex(filename)

    row_clues = [[] for _ in range(ROWS)]
    col_clues = [[] for _ in range(COLS)]

    # -------- Columns (lookaheads) --------
    parts = regex_str.split("(?=")
    for part in parts:
        if not part.startswith("(?:"):
            continue

        blocks = re.findall(r"\(\?:(.+?)\)(?:\{(\d+)\})?", part)
        if not blocks:
            continue

        first_body = blocks[0][0]
        m_sep = re.search(r"\\\.|#", first_body)  # match '\.' or '#'
        if not m_sep:
            continue

        prefix = first_body[: m_sep.start()]
        if prefix == "":
            offset = 0
        elif prefix == ".":
            offset = 1
        else:
            m_len = re.match(r"\.\{(\d+)\}", prefix)  # literal .{N}
            if not m_len:
                continue
            offset = int(m_len.group(1))

        if not (0 <= offset < COLS):
            continue

        clues = []
        for body, quant_str in blocks:
            if "#" in body:
                clues.append(int(quant_str) if quant_str else 1)
        col_clues[offset] = clues

    # -------- Rows (lookbehinds + capturing group per row) --------
    # Matches: (?<=.{101})(?<!.{102})(\.*#{2}\.+#\.+... \.*)
    row_pat = re.compile(r"\(\?<=\.\{(\d+)\}\)(?:\(\?<\!\.\{\d+\}\))?\(([^)]*)\)")
    for m in row_pat.finditer(regex_str):
        offset_val = int(m.group(1))
        row_idx = offset_val // COLS
        if not (0 <= row_idx < ROWS):
            continue

        body = m.group(2)
        clues = []
        for hm in re.finditer(r"#(?:\{(\d+)\})?", body):
            clues.append(int(hm.group(1) or 1))
        row_clues[row_idx] = clues

    return row_clues, col_clues

def solve_line(length, clues, current_line):
    """
    current_line: list of -1/0/1
    returns: new_line (list) or None if contradiction
    """
    memo = {}

    def can_match(pos, clue_idx):
        pos = min(pos, length)
        key = (pos, clue_idx)
        if key in memo:
            return memo[key]

        if clue_idx == len(clues):
            ok = all(current_line[k] != 1 for k in range(pos, length))
            memo[key] = ok
            return ok

        clue = clues[clue_idx]
        remain = sum(clues[clue_idx:]) + (len(clues) - 1 - clue_idx)

        for start in range(pos, length - remain + 1):
            # gap [pos, start) must be empty
            for k in range(pos, start):
                if current_line[k] == 1:
                    memo[key] = False
                    return False  # increasing start won't help

            end = start + clue
            if end > length:
                break

            # block [start, end) must be filled
            bad = False
            for k in range(start, end):
                if current_line[k] == 0:
                    bad = True
                    break
            if bad:
                continue

            # cell after block must be empty (if exists)
            if end < length and current_line[end] == 1:
                continue

            next_pos = end + 1 if end < length else length
            if can_match(next_pos, clue_idx + 1):
                memo[key] = True
                return True

        memo[key] = False
        return False

    if not can_match(0, 0):
        return None

    counts_0 = [False] * length
    counts_1 = [False] * length
    visited = set()

    def build(pos, clue_idx):
        pos = min(pos, length)
        state = (pos, clue_idx)
        if state in visited:
            return
        visited.add(state)

        if clue_idx == len(clues):
            for k in range(pos, length):
                counts_0[k] = True
            return

        clue = clues[clue_idx]
        remain = sum(clues[clue_idx:]) + (len(clues) - 1 - clue_idx)

        for start in range(pos, length - remain + 1):
            for k in range(pos, start):
                if current_line[k] == 1:
                    return  # increasing start won't help

            end = start + clue
            if end > length:
                break

            bad = False
            for k in range(start, end):
                if current_line[k] == 0:
                    bad = True
                    break
            if bad:
                continue

            if end < length and current_line[end] == 1:
                continue

            next_pos = end + 1 if end < length else length
            if not can_match(next_pos, clue_idx + 1):
                continue

            for k in range(pos, start):
                counts_0[k] = True
            for k in range(start, end):
                counts_1[k] = True
            if end < length:
                counts_0[end] = True

            build(next_pos, clue_idx + 1)

    build(0, 0)

    new_line = current_line[:]
    for i in range(length):
        if current_line[i] != -1:
            continue
        if counts_1[i] and counts_0[i]:
            new_line[i] = -1
        elif counts_1[i]:
            new_line[i] = 1
        elif counts_0[i]:
            new_line[i] = 0
        else:
            new_line[i] = -1
    return new_line

def propagate(grid, row_clues, col_clues):
    rows = len(grid)
    cols = len(grid[0])
    changed = True
    while changed:
        changed = False

        for r in range(rows):
            nl = solve_line(cols, row_clues[r], grid[r])
            if nl is None:
                return None
            if nl != grid[r]:
                grid[r] = nl
                changed = True

        for c in range(cols):
            cur = [grid[r][c] for r in range(rows)]
            nl = solve_line(rows, col_clues[c], cur)
            if nl is None:
                return None
            if nl != cur:
                for r in range(rows):
                    grid[r][c] = nl[r]
                changed = True
    return grid

def choose_branch_cell(grid):
    # heuristic: pick row with fewest unknowns (>0), then first unknown in it
    best_r = None
    best_unk = 10**9
    for r, row in enumerate(grid):
        unk = sum(1 for v in row if v == -1)
        if 0 < unk < best_unk:
            best_unk = unk
            best_r = r
    if best_r is None:
        return None
    for c, v in enumerate(grid[best_r]):
        if v == -1:
            return (best_r, c)
    return None

def solve_grid(grid, row_clues, col_clues):
    grid = propagate([row[:] for row in grid], row_clues, col_clues)
    if grid is None:
        return None

    pos = choose_branch_cell(grid)
    if pos is None:
        return grid

    r, c = pos
    for val in (0, 1):
        g2 = [row[:] for row in grid]
        g2[r][c] = val
        res = solve_grid(g2, row_clues, col_clues)
        if res is not None:
            return res
    return None

def main():
    print("Đang phân tích regex -> nonogram clues...")
    row_clues, col_clues = parse_regex_constraints()

    grid = [[-1] * COLS for _ in range(ROWS)]
    grid[0] = [0] * COLS  # row0 is (\.*)

    print("Đang solve nonogram (propagate + backtracking)...")
    solved = solve_grid(grid, row_clues, col_clues)
    if solved is None:
        print("Không giải được (mâu thuẫn).")
        return

    print("\n--- PIXEL FLAG ---")
    for r in range(ROWS):
        print("".join("█" if solved[r][c] == 1 else " " for c in range(COLS)))

    # s = "".join("#" if solved[r][c] == 1 else "." for r in range(ROWS) for c in range(COLS))
    # print("\n--- raw input (1919 chars) ---")
    # print(s)

if __name__ == "__main__":
    main()