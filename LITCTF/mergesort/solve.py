# Reconstruct seed from output.txt's md array using backtracking on the mgs logic.
from pathlib import Path
data = Path('output.txt').read_text()
print(data.splitlines()[:6])
# parse md line from file (we know format)
lines = data.splitlines()
# find the line starting with "md:" and the following line contains numbers
md_index = None
for i,line in enumerate(lines):
    if line.strip() == "md:":
        md_index = i+1
        break
if md_index is None:
    raise RuntimeError("md not found")
md_line = lines[md_index].strip()
# md numbers separated by commas possibly ending with trailing comma
md_nums = [int(x.strip()) for x in md_line.split(',') if x.strip()!='']
print("First few md numbers:", md_nums[:10], "count:", len(md_nums))

# Backtracking parser
from functools import lru_cache

md = md_nums

# parse(n, depth, idx) -> returns list of digits (in order consumed) and new idx if possible, else None
def try_parse(n, depth, idx):
    # if depth >=4 and n>=2, expect md[idx]==n and consume
    if depth >= 4:
        if n >= 2:
            if idx < len(md) and md[idx] == n:
                return [], idx+1
            else:
                return None
        else:
            # n<=1 nothing to output
            return [], idx
    # depth <4
    if n < 2:
        # nothing happens
        return [], idx
    # need to choose digit d in 1..9 such that left_count = (n*d)//10
    for d in range(1,10):
        left = (n * d) // 10
        right = n - left
        # if left==0 then left recursion won't run; but that's allowed
        # parse left then right
        res_left = try_parse(left, depth+1, idx)
        if res_left is None:
            continue
        digits_left, idx_after_left = res_left
        res_right = try_parse(right, depth+1, idx_after_left)
        if res_right is None:
            continue
        digits_right, idx_after_right = res_right
        # success: current node consumes digit d followed by children digits
        return [d] + digits_left + digits_right, idx_after_right
    return None

# Top-level n = 10000, depth=0, idx=0
res = try_parse(10000, 0, 0)
if res is None:
    print("No parse found")
else:
    digits, final_idx = res
    print("Found digits count:", len(digits), "final_idx:", final_idx)
    print("Digits (LSB first):", digits)
    # compute seed from digits: each digit = (seed %9)+1 so seed_base9_digit = d-1, least significant first
    seed = 0
    mul = 1
    for d in digits:
        seed += (d-1) * mul
        mul *= 9
    print("Recovered minimal seed (using only consumed digits):", seed)
    print("As base10 flag:", f"LITCTF{{{seed}}}")
