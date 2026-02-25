from __future__ import annotations

import io
import math
import zipfile
from dataclasses import dataclass
from typing import List, Tuple

from PIL import Image, ImageOps

FILENAME = "signal.bin"

TIMING_W, TIMING_H = 800, 525
ACTIVE_W, ACTIVE_H = 640, 480
BPS = 5
PAYLOAD_LEN = TIMING_W * TIMING_H * BPS

# VGA-ish porch/sync lengths (pixel clocks / lines)
H_FRONT, H_SYNC, H_BACK = 16, 96, 48
V_FRONT, V_SYNC, V_BACK = 10, 2, 33


def extract_embedded_zip(blob: bytes) -> None:
    zoff = blob.rfind(b"PK\x03\x04")
    if zoff == -1:
        return
    try:
        zf = zipfile.ZipFile(io.BytesIO(blob[zoff:]))
        if "hint.txt" in zf.namelist():
            hint = zf.read("hint.txt").decode("utf-8", errors="replace")
            print("[hint.txt]\n" + hint.strip() + "\n")
    except Exception:
        pass


def payload_slice(blob: bytes) -> bytes:
    end = blob.rfind(b"PK\x03\x04")
    if end == -1:
        end = len(blob)
    start = end - PAYLOAD_LEN
    if start < 0:
        raise RuntimeError("payload too small")
    print(f"[*] Using payload slice [{start}:{end}] len={end-start}")
    return blob[start:end]


def median(xs: List[int]) -> float:
    ys = sorted(xs)
    n = len(ys)
    if n == 0:
        return 0.0
    if n % 2 == 1:
        return float(ys[n // 2])
    return 0.5 * (ys[n // 2 - 1] + ys[n // 2])


def best_run_near_target(sig: bytes, target: int) -> Tuple[int, int, int]:
    """
    sig: length N bytes. We binarize by threshold=median.
    returns (start,end,len) of the run whose length is closest to target.
    """
    if not sig:
        return (0, 0, 0)

    thr = median(list(sig))
    # binarize on the fly
    best = (10**9, 0, 0, 0)  # (diff, start, end, length)

    cur_level = 1 if sig[0] > thr else 0
    cur_start = 0

    for i in range(1, len(sig) + 1):
        level = cur_level if i == len(sig) else (1 if sig[i] > thr else 0)
        if i == len(sig) or level != cur_level:
            length = i - cur_start
            diff = abs(length - target)
            if diff < best[0]:
                best = (diff, cur_start, i, length)
            if i != len(sig):
                cur_level = level
                cur_start = i

    return (best[1], best[2], best[3])


def pick_hsync_channel(payload: bytes) -> int:
    """
    Decide whether byte3 or byte4 behaves like HSYNC (pulse ~96 each line).
    Returns control index in sample: 3 or 4.
    """
    def score_channel(ctrl_idx: int) -> float:
        good = 0
        total = 0
        diffs = []
        for y in range(TIMING_H):
            line = payload[y * TIMING_W * BPS : (y + 1) * TIMING_W * BPS]
            sig = line[ctrl_idx::BPS]  # 800 bytes
            s, e, ln = best_run_near_target(sig, H_SYNC)
            total += 1
            d = abs(ln - H_SYNC)
            diffs.append(d)
            if d <= 20:
                good += 1
        # prefer many good lines + smaller median diff
        return good * 1000.0 - median(diffs)

    s3 = score_channel(3)
    s4 = score_channel(4)
    hidx = 3 if s3 >= s4 else 4
    print(f"[*] HSYNC channel looks like byte{hidx} (score3={s3:.1f} score4={s4:.1f})")
    return hidx


def pick_vsync_channel(hsync_idx: int) -> int:
    return 4 if hsync_idx == 3 else 3


def estimate_hsync_position(payload: bytes, hsync_idx: int) -> Tuple[int, int]:
    """
    Returns typical (sync_start, sync_end) within a line by taking median across lines.
    """
    starts, ends = [], []
    for y in range(TIMING_H):
        line = payload[y * TIMING_W * BPS : (y + 1) * TIMING_W * BPS]
        sig = line[hsync_idx::BPS]
        s, e, ln = best_run_near_target(sig, H_SYNC)
        if abs(ln - H_SYNC) <= 20:
            starts.append(s)
            ends.append(e)
    if not starts:
        # fallback
        return (0, H_SYNC)
    return (int(median(starts)), int(median(ends)))


def estimate_vsync_lines(payload: bytes, vsync_idx: int) -> Tuple[int, int]:
    """
    Use per-line median to binarize vsync-ish signal and find run near 2 lines.
    Returns (sync_start_line, sync_end_line).
    """
    per_line = []
    for y in range(TIMING_H):
        line = payload[y * TIMING_W * BPS : (y + 1) * TIMING_W * BPS]
        sig = line[vsync_idx::BPS]
        per_line.append(int(median(list(sig))))

    thr = median(per_line)
    bits = [1 if v > thr else 0 for v in per_line]

    # find run whose len closest to V_SYNC
    best = (10**9, 0, 0, 0)
    cur = bits[0]
    st = 0
    for i in range(1, len(bits) + 1):
        lvl = cur if i == len(bits) else bits[i]
        if i == len(bits) or lvl != cur:
            ln = i - st
            diff = abs(ln - V_SYNC)
            if diff < best[0]:
                best = (diff, st, i, ln)
            if i != len(bits):
                cur = lvl
                st = i

    _, s, e, ln = best
    print(f"[*] VSYNC run ~{ln} lines at y=[{s},{e}) (thr={thr:.1f})")
    return (s, e)


def extract_active_image(
    payload: bytes,
    x0: int,
    y0: int,
    rgb_order: str,
) -> Image.Image:
    """
    x0,y0 are active top-left in timing space (with wrap allowed).
    rgb_order: "RGB" or "BGR"
    """
    out = bytearray(ACTIVE_W * ACTIVE_H * 3)
    j = 0

    for row in range(ACTIVE_H):
        yy = (y0 + row) % TIMING_H
        base_line = yy * TIMING_W * BPS

        for col in range(ACTIVE_W):
            xx = (x0 + col) % TIMING_W
            i = base_line + xx * BPS
            b0, b1, b2 = payload[i], payload[i + 1], payload[i + 2]

            if rgb_order == "RGB":
                r, g, b = b0, b1, b2
            else:
                b, g, r = b0, b1, b2

            out[j] = r
            out[j + 1] = g
            out[j + 2] = b
            j += 3

    return Image.frombytes("RGB", (ACTIVE_W, ACTIVE_H), bytes(out))


def score_image(img: Image.Image) -> float:
    g = ImageOps.grayscale(img)
    data = g.tobytes()
    if not data:
        return -1e9
    # cheap: prefer higher contrast and some bright pixels (text)
    step = 64
    samp = data[0::step]
    n = len(samp)
    mean = sum(samp) / n
    var = sum((p - mean) ** 2 for p in samp) / n
    std = math.sqrt(var)
    white = sum(1 for p in samp if p > 230) / n
    black = sum(1 for p in samp if p < 25) / n
    return std * 1.0 + white * 200.0 + black * 20.0


@dataclass
class Best:
    score: float
    x0: int
    y0: int
    order: str
    img: Image.Image


def main():
    blob = open(FILENAME, "rb").read()
    print(f"[*] file={FILENAME} size={len(blob)} bytes")
    extract_embedded_zip(blob)

    payload = payload_slice(blob)

    hidx = pick_hsync_channel(payload)
    vidx = pick_vsync_channel(hidx)

    hs_s, hs_e = estimate_hsync_position(payload, hidx)
    vs_s, vs_e = estimate_vsync_lines(payload, vidx)

    # Two plausible x origins relative to HSYNC pulse
    # 1) if file line starts at sync start: active begins at sync_end + backporch
    x_candidates = [
        (hs_e + H_BACK) % TIMING_W,
        # 2) if sync is after active: active starts at sync_start - front - active
        (hs_s - H_FRONT - ACTIVE_W) % TIMING_W,
    ]

    # Two plausible y origins relative to VSYNC pulse
    y_candidates = [
        (vs_e + V_BACK) % TIMING_H,
        (vs_s - V_FRONT - ACTIVE_H) % TIMING_H,
    ]

    best: Best | None = None
    for order in ("RGB", "BGR"):
        for x0 in x_candidates:
            for y0 in y_candidates:
                img = extract_active_image(payload, x0, y0, order)
                s = score_image(img)
                if best is None or s > best.score:
                    best = Best(s, x0, y0, order, img)

    assert best is not None
    print(f"[+] BEST order={best.order} x0={best.x0} y0={best.y0} score={best.score:.2f}")

    best.img.save("solved_flag.png")
    ImageOps.autocontrast(best.img).save("solved_flag_autocontrast.png")

    try:
        ImageOps.autocontrast(best.img).show()
    except Exception:
        pass

    print("[+] Wrote solved_flag.png / solved_flag_autocontrast.png")


if __name__ == "__main__":
    main()