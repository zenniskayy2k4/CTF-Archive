#!/usr/bin/env python3
# recover_from_image.py
# Usage: python recover_from_image.py verrou_output.png

import sys
from PIL import Image
import numpy as np
import binascii

EXPECTED_W = 313
EXPECTED_H = 40
BITS_NEEDED = EXPECTED_W * EXPECTED_H  # 12520

def load_and_binarize(path):
    img = Image.open(path).convert("L")  # grayscale
    w,h = img.size
    # If image already at expected size -> don't resize; otherwise resize with NEAREST to preserve modules.
    if (w,h) != (EXPECTED_W, EXPECTED_H):
        # If image is a scaled-up version (usual in CV pipelines), nearest neighbor keeps modules.
        img = img.resize((EXPECTED_W, EXPECTED_H), resample=Image.NEAREST)
    arr = np.array(img, dtype=np.uint8)
    # threshold at 128
    bw = (arr > 128).astype(np.uint8)  # white -> 1, black -> 0
    # According to decomp: bit==1 -> pixel 0xff (white). So bw==1 => bit=1. OK.
    return bw

def bits_from_matrix(bw):
    # bw shape (H, W) but decomp used rows=40, cols=313: careful ordering -> we used (W,H) earlier, but PIL gives (W,H) as size and array as (H,W).
    H, W = bw.shape
    assert (W, H) == (EXPECTED_W, EXPECTED_H) or (H, W) == (EXPECTED_H, EXPECTED_W), \
        f"Unexpected shape {bw.shape}"
    # ensure row-major order: top-to-bottom rows, left-to-right cols
    bits = bw.reshape(-1).tolist()  # this is row-major flattening
    # Ensure we have at least BITS_NEEDED bits
    if len(bits) < BITS_NEEDED:
        raise ValueError("Not enough pixels to extract bits.")
    return bits[:BITS_NEEDED]

def pack_bits_lsb_first(bits):
    # bits is list of 0/1, length multiple of 8? maybe not; we pack groups of 8 LSB-first
    out_bytes = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        chunk = bits[i:i+8]
        # pad with zeros if last chunk < 8
        if len(chunk) < 8:
            chunk += [0] * (8 - len(chunk))
        for k, b in enumerate(chunk):
            byte |= (int(b) & 1) << k   # LSB-first: bit0 is chunk[0]
        out_bytes.append(byte)
    return bytes(out_bytes)

def main():
    if len(sys.argv) < 2:
        print("Usage: python recover_from_image.py <image_file>")
        sys.exit(1)
    path = sys.argv[1]
    bw = load_and_binarize(path)
    bits = bits_from_matrix(bw)
    data = pack_bits_lsb_first(bits)
    outname = "recovered.bin"
    with open(outname, "wb") as f:
        f.write(data)
    print(f"Wrote {len(data)} bytes to {outname}")
    # print small preview
    # print("First 256 bytes (hex):")
    # print(binascii.hexlify(data[:256]).decode())
    # Try to show printable ASCII excerpt
    s = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[:200])
    # print("ASCII preview:", s)

if __name__ == "__main__":
    main()
