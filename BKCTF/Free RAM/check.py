def ror8(val, shift):
    shift = shift % 8
    # Thực hiện xoay phải 8-bit
    return ((val >> shift) | (val << (8 - shift))) & 0xFF

# Chuỗi plaintext gốc mà ta biết chắc chắn nó nằm ở đầu file
known_pt = b"the quick brown fox jumps over the lazy dog"

# known_pt = b"%PDF-"
# open("my_files/school_stuff/stack_smashing.pdf", "rb")

# Đọc file đã bị mã hóa
with open("my_files/school_stuff/quick_brown_fox.txt", "rb") as f:
    enc_data = f.read()

# Kiểm tra và bỏ qua byte marker 'g' đầu file
if enc_data[0] == ord('g'):
    enc_data = enc_data[1:]

key_extracted = []
# Lặp qua từng byte để tính ngược ra Key
for i in range(min(len(known_pt), len(enc_data))):
    e = enc_data[i]
    p = known_pt[i]
    
    # Tính toán lại Key: K[i] = ROR8(E[i], i % 8) ^ P[i]
    k_byte = ror8(e, i) ^ p
    key_extracted.append(chr(k_byte))

print("Key stream extracted:", "".join(key_extracted))