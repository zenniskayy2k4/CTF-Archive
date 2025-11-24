# Dữ liệu từ file main.rs
TARGET = [
    0x15, 0x5A, 0xAC, 0xF6, 0x36, 0x22, 0x3B, 0x52, 0x6C, 0x4F, 0x90, 0xD9, 0x35, 0x63, 0xF8, 0x0E, 
    0x02, 0x33, 0xB0, 0xF1, 0xB7, 0x69, 0x42, 0x67, 0x25, 0xEA, 0x96, 0x63, 0x1B, 0xA7, 0x03, 0x0B
]

XOR_KEY = [0x7E, 0x33, 0x91, 0x4C, 0xA5]
ROTATION_PATTERN = [1, 3, 5, 7, 2, 4, 6]
MAGIC_SUB = 0x5D

def rotate_right(val, n):
    """Đảo ngược của Rotate Left là Rotate Right"""
    n = n % 8
    return ((val >> n) | (val << (8 - n))) & 0xFF

def solve():
    # Copy target vào buffer để xử lý
    buf = list(TARGET)

    # --- 1. Đảo ngược Step 6 (Coordinate Calibration) ---
    # Forward: XOR với (index^2 % 256)
    # Reverse: XOR lại với giá trị đó
    for i in range(len(buf)):
        pos_squared = (i * i) % 256
        buf[i] ^= pos_squared

    # --- 2. Đảo ngược Step 5 (Temporal Inversion) ---
    # Forward: Reverse từng chunk 5 byte
    # Reverse: Reverse lại lần nữa
    chunk_size = 5
    for i in range(0, len(buf), chunk_size):
        # Lấy đoạn chunk và đảo ngược nó
        buf[i:i+chunk_size] = buf[i:i+chunk_size][::-1]

    # --- 3. Đảo ngược Step 4 (Gravitational Shift) ---
    # Forward: Trừ MAGIC_SUB
    # Reverse: Cộng MAGIC_SUB (mod 256)
    for i in range(len(buf)):
        buf[i] = (buf[i] + MAGIC_SUB) % 256

    # --- 4. Đảo ngược Step 3 (Spatial Transposition) ---
    # Forward: Swap các cặp (0,1), (2,3)...
    # Reverse: Swap lại lần nữa
    for i in range(0, len(buf), 2):
        if i + 1 < len(buf):
            buf[i], buf[i+1] = buf[i+1], buf[i]

    # --- 5. Đảo ngược Step 2 (Stellar Rotation) ---
    # Forward: Rotate Left theo pattern
    # Reverse: Rotate Right theo pattern
    for i in range(len(buf)):
        rot = ROTATION_PATTERN[i % 7]
        buf[i] = rotate_right(buf[i], rot)

    # --- 6. Đảo ngược Step 1 (Quantum Cipher) ---
    # Forward: XOR với Key
    # Reverse: XOR lại với Key
    for i in range(len(buf)):
        buf[i] ^= XOR_KEY[i % 5]

    # Kết quả
    flag = "".join(chr(x) for x in buf)
    print(f"Flag tìm được: {flag}")

if __name__ == "__main__":
    solve()