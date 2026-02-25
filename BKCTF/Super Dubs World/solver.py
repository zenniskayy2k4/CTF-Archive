import zlib
import os

print("🍄 MÁY DÒ MẢNH GHÉP TỐI THƯỢNG 🍄\n")

def find_pieces(filepath):
    if not os.path.exists(filepath):
        return
    print(f"[*] Đang lùng sục mọi ngóc ngách của: {filepath}")
    with open(filepath, 'rb') as f:
        data = f.read()

    # Chỉ cần thấy số 2: hoặc 3: là tóm cổ ngay lập tức!
    targets = [b'[1:', b'[2:', b'[3:', b'[4:', b'[5:', b'2:', b'3:']

    def check_and_print(buffer, source_name):
        for t in targets:
            idx = buffer.find(t)
            while idx != -1:
                # Cắt lấy 30 ký tự xung quanh để xem
                start = max(0, idx - 5)
                end = min(len(buffer), idx + 25)
                snippet = buffer[start:end]
                
                try:
                    text = snippet.decode('utf-8')
                    # Lọc bớt rác nhị phân (nếu chữ đọc được thì mới in)
                    if sum(1 for c in text if ord(c) < 32 and c not in '\r\n\t') < 2:
                         print(f"  -> Bắt được tình nghi '{t.decode()}' ở {source_name}: {text.strip()}")
                except:
                    pass
                idx = buffer.find(t, idx + 1)

    # 1. Quét thẳng mặt Plaintext (Vùng chứa Exif, HTML ẩn, Metadata, ZIP Comment...)
    check_and_print(data, "Vùng Plaintext/Metadata")

    # 2. Quét mọi luồng nén Zlib
    magic_headers = [b'\x78\x9c', b'\x78\xda', b'\x78\x01', b'\x78\x5e']
    for i in range(len(data) - 2):
        if data[i:i+2] in magic_headers:
            try:
                dobj = zlib.decompressobj()
                decompressed = dobj.decompress(data[i:])
                check_and_print(decompressed, f"Luồng nén Zlib")
            except Exception:
                pass

# Quét cả 2 lớp file
find_pieces("dubs.pdf")
if os.path.exists("_dubs.pdf.extracted/dubs.pdf"):
    find_pieces("_dubs.pdf.extracted/dubs.pdf")
elif os.path.exists("dubs_layer1.pdf"):
    find_pieces("dubs_layer1.pdf")