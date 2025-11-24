from scapy.all import rdpcap, DNSQR, DNS
from PIL import Image
from hashlib import sha512

# --- Phần 1: Trích xuất TOÀN BỘ 9900 mảnh ---
pcap_file = "capture.pcap"
domain_suffix = ".dat2phit.kro.kr."
all_chunks = []

print(f"Đang đọc file {pcap_file} và trích xuất toàn bộ 9900 mảnh...")
try:
    packets = rdpcap(pcap_file)
except FileNotFoundError:
    print(f"Lỗi: Không tìm thấy file '{pcap_file}'.")
    exit()

for packet in packets:
    if packet.haslayer(DNS) and packet[DNS].qr == 0:
        qname = packet[DNSQR].qname.decode('utf-8')
        if qname.endswith(domain_suffix):
            all_chunks.append(qname[:-len(domain_suffix)])

print(f"Đã trích xuất được {len(all_chunks)} mảnh dữ liệu.")

# --- Phần 2: SẮP XẾP và Tái tạo Hash ---
# Đây là bước quan trọng nhất, mô phỏng lại "magic" của kẻ tấn công
print("Đang sắp xếp lại toàn bộ 9900 mảnh theo thứ tự bảng chữ cái...")
sorted_chunks = sorted(all_chunks)

# Nối các mảnh đã sắp xếp lại
raw_data_stream = "".join(sorted_chunks)

# Cắt thành các hash 128-ký-tự
hash_length = 128
reconstructed_hashes = []
for i in range(0, len(raw_data_stream), hash_length):
    single_hash = raw_data_stream[i:i + hash_length]
    if len(single_hash) == hash_length:
        reconstructed_hashes.append(single_hash)

print(f"Đã tái tạo thành công {len(reconstructed_hashes)} chuỗi hash sau khi sắp xếp.")

# --- Phần 3: Tạo bảng tra cứu và Giải mã ---
pad = b"XfilTr4T3_"
def encrypt1(m):
  return sha512(pad + str(m).encode()).hexdigest()

print("Đang tạo bảng tra cứu...")
lookup_table = {encrypt1(i): i for i in range(256)}
print("Tạo bảng tra cứu hoàn tất!")

recovered_pixels = []
# Chúng ta chỉ quan tâm đến nửa đầu của các hash đã sắp xếp, vì đó là của encrypt1
# Nửa đầu = 1100 hashes
for h in reconstructed_hashes[:1100]:
    if h in lookup_table:
        recovered_pixels.append(lookup_table[h])

print(f"!!! ĐÃ KHÔI PHỤC THÀNH CÔNG {len(recovered_pixels)} PIXELS !!!")

# --- Phần 4: Tái tạo ảnh ---
if len(recovered_pixels) > 100:
    total_pixels = len(recovered_pixels)
    print(f"Đang tìm kích thước ảnh (tổng số pixel = {total_pixels})...")
    # Tìm các ước của tổng số pixel (1100)
    for width in range(20, 100):
        if total_pixels % width == 0:
            height = total_pixels // width
            print(f"==> KÍCH THƯỚC KHẢ THI: {width}x{height}")
            img = Image.new('L', (width, height))
            img.putdata(recovered_pixels)
            output_filename = f"FLAG_RECOVERED_{width}x{height}.png"
            img.save(output_filename)
            print(f"    Đã lưu ảnh tại: {output_filename}")
else:
    print("Thất bại. Logic cuối cùng vẫn chưa đúng.")