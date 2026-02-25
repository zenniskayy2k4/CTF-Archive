import re
from pathlib import Path
import matplotlib.pyplot as plt

VERILOG_PATH = Path("v.v")
OUT_PATH = Path("flag.png")
N = 128  # 7-bit grid

code = VERILOG_PATH.read_text(encoding="utf-8", errors="ignore")

# capture optional "7'd" prefix for x and y separately
pattern = r"x\s*==\s*(?:(7'd))?(\d+)\s*&&\s*y\s*==\s*(?:(7'd))?(\d+)"
matches = re.findall(pattern, code)

img = [[255 for _ in range(N)] for __ in range(N)]  # white background
kept = 0

def eval_const(prefix_7d: str, num_str: str) -> int | None:
    v = int(num_str)
    if prefix_7d:              # sized 7-bit constant => truncated
        return v & 0x7F
    # unsized constant is 32-bit-ish; only reachable if < 128
    if 0 <= v < N:
        return v
    return None

for x7d, xs, y7d, ys in matches:
    xv = eval_const(x7d, xs)
    yv = eval_const(y7d, ys)
    if xv is None or yv is None:
        continue
    img[yv][xv] = 0            # black pixel
    kept += 1

print(f"Total conditions found: {len(matches)}")
print(f"Reachable pixels kept (on 7-bit grid): {kept}")
print(f"Saved to: {OUT_PATH.resolve()}")

plt.imsave(OUT_PATH, img, cmap="gray", vmin=0, vmax=255)