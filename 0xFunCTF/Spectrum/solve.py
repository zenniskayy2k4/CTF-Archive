import wave
import struct

with wave.open('audio.wav', 'rb') as f:
    # Đọc toàn bộ frames
    frames = f.readframes(f.getnframes())
    # Unpack dữ liệu 16-bit (little-endian signed short)
    samples = struct.unpack(f'<{len(frames)//2}h', frames)

# Trích xuất bit cuối cùng của mỗi sample
bits = [str(s & 1) for s in samples]
binary_str = "".join(bits)

# Chuyển đổi chuỗi bit thành ký tự ASCII
def binary_to_text(bin_data):
    chars = []
    for i in range(0, len(bin_data), 8):
        byte = bin_data[i:i+8]
        if len(byte) == 8:
            chars.append(chr(int(byte, 2)))
    return "".join(chars)

extracted = binary_to_text(binary_str)
# Tìm kiếm pattern của flag (ví dụ: 0xfun{)
if "0xfun{" in extracted:
    print(extracted[extracted.find("0xfun{"):extracted.find("}")+1])
else:
    print("Không tìm thấy flag định dạng 0xfun{ trong LSB.")