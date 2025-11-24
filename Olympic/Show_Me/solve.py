# solve_qr.py
import binascii
import numpy as np
from PIL import Image
import sys

def reconstruct_matrix_from_hex(qr_hex, size=29):
    # hex -> bytes
    data = binascii.unhexlify(qr_hex)
    # each row has ceil(size/8) bytes -> here 4 bytes (32 bits)
    bytes_per_row = (size + 7) // 8  # 4
    expected_len = size * bytes_per_row
    if len(data) < expected_len:
        raise ValueError(f"Not enough bytes: got {len(data)}, expected {expected_len}")
    bits = []
    idx = 0
    for row in range(size):
        for b in range(bytes_per_row):
            byte = data[idx]
            idx += 1
            # MSB first: extract bit7..bit0
            for k in range(8):
                col = b*8 + k
                if col < size:
                    bit = (byte >> (7 - k)) & 1
                    bits.append(bit)
                # else padding bit -> ignore
    arr = np.array(bits, dtype=np.uint8).reshape((size, size))
    return arr

def save_qr_image(matrix, scale=10, quiet_zone=4, outname="qr.png"):
    # matrix: 0/1 where 1 means black module
    # image pixel: 0=black,255=white -> invert matrix
    mod = (1 - matrix) * 255  # now black=0, white=255
    h, w = mod.shape
    # add quiet zone (white)
    new_h = h + 2*quiet_zone
    new_w = w + 2*quiet_zone
    canvas = np.full((new_h, new_w), 255, dtype=np.uint8)
    canvas[quiet_zone:quiet_zone+h, quiet_zone:quiet_zone+w] = mod
    # scale
    canvas_scaled = np.repeat(np.repeat(canvas, scale, axis=0), scale, axis=1)
    img = Image.fromarray(canvas_scaled, mode="L")
    img.save(outname)
    print(f"Saved QR to {outname} (size: {canvas_scaled.shape})")

def main():
    s = "9e5bc5216b4d19feeb53f882e2f208bab142e8bad472e8ba03c2e8829ad208feaaabf8004bf800ce16017881eb55f0b71f2ee811b5fd48b32c1c08254713c06be14a68546b6240c7361880ad0897b032bf828819554948df2c0fe000c6d8c0fe612a8882ca7890bad71f90ba48d568ba7f327882b4e0d8feec0f30"

    # Sometimes the output is like "<14hex><qrhex>" or contains whitespace.
    s = ''.join(s.split())  # remove spaces/newlines
    # if there is non-hex leading (like 'Ciphertext:'), try to find first hex char
    import re
    m = re.search(r'[0-9a-fA-F]{20,}', s)
    if m:
        s = m.group(0)

    # If length > expected, assume first 14 chars are random prefix (hex ascii), remove them
    # Expected QR hex length: size*bytes_per_row*2 = 29*4*2 = 232
    size = 29
    bytes_per_row = (size + 7) // 8
    expected_hex_len = size * bytes_per_row * 2  # 232
    if len(s) == expected_hex_len + 14:
        print("Detected 14-char random prefix -> stripping first 14 hex chars.")
        s = s[14:]
    elif len(s) > expected_hex_len and len(s) % 2 == 0:
        # if longer, try to find a substring at end of expected_hex_len
        possible = s[-expected_hex_len:]
        print("Using last {} hex chars as QR data.".format(expected_hex_len))
        s = possible
    elif len(s) != expected_hex_len:
        print(f"Warning: input length {len(s)} != expected {expected_hex_len}. Attempting to use full string anyway.")

    try:
        mat = reconstruct_matrix_from_hex(s, size=size)
    except Exception as e:
        print("Error reconstructing matrix:", e)
        return

    save_qr_image(mat, scale=10, quiet_zone=4, outname="qr.png")
    print("Done. Open qr.png and scan it (phone or zbarimg).")

if __name__ == "__main__":
    main()