import zlib
import socket
from scapy.all import rdpcap, ICMPv6ND_NS, ICMPv6ND_NA

# Đường dẫn đến file pcap của bạn
PCAP_FILE = 'dump.pcapng'

# Tiền tố của các địa chỉ IPv6 chứa dữ liệu
IPV6_PREFIX = 'fd01:5ffa:'

def solve_6pack_final():
    """
    Hàm đọc file pcap, trích xuất dữ liệu từ trường Target Address của các gói
    Neighbor Solicitation và Neighbor Advertisement, sau đó giải nén.
    """
    print(f"[*] Phân tích file: {PCAP_FILE}")
    
    try:
        packets = rdpcap(PCAP_FILE)
    except Exception as e:
        print(f"[!] Lỗi: không thể đọc file pcap. Đảm bảo file '{PCAP_FILE}' tồn tại.")
        print(f"   Chi tiết lỗi: {e}")
        return

    print(f"[*] Đã đọc thành công {len(packets)} gói tin.")
    
    encrypted_stream = b''
    found_packets = 0
    
    # Tạo một danh sách để lưu các gói tin và sắp xếp chúng theo thời gian
    # để đảm bảo thứ tự là chính xác.
    potential_packets = []
    for pkt in packets:
        if ICMPv6ND_NS in pkt or ICMPv6ND_NA in pkt:
            potential_packets.append(pkt)

    print(f"[*] Tìm thấy {len(potential_packets)} gói tin Neighbor Discovery (NS/NA).")

    # Sắp xếp các gói tin theo timestamp để đảm bảo thứ tự chính xác
    potential_packets.sort(key=lambda p: p.time)

    # Xử lý các gói tin đã sắp xếp
    for pkt in potential_packets:
        address_to_check = None
        
        if ICMPv6ND_NS in pkt:
            address_to_check = pkt[ICMPv6ND_NS].tgt
        elif ICMPv6ND_NA in pkt:
            address_to_check = pkt[ICMPv6ND_NA].tgt
        
        if address_to_check and isinstance(address_to_check, str):
            if address_to_check.lower().startswith(IPV6_PREFIX.lower()):
                try:
                    # Chuyển đổi địa chỉ sang dạng byte
                    ip_bytes = socket.inet_pton(socket.AF_INET6, address_to_check)
                    
                    # Trích xuất chunk dữ liệu từ byte thứ 5 và 6
                    data_chunk = ip_bytes[4:6]
                    
                    encrypted_stream += data_chunk
                    found_packets += 1
                except (socket.error, TypeError):
                    pass

    if not encrypted_stream:
        print("\n[!] Không tìm thấy dữ liệu nào được mã hóa trong trường Target Address.")
        return

    print(f"[*] Đã trích xuất thành công {len(encrypted_stream)} bytes từ {found_packets} gói tin.")
    print("[*] Đang tiến hành giải nén...")

    try:
        # Giải nén luồng dữ liệu bằng zlib
        decompressed_data = zlib.decompress(encrypted_stream)
        
        print("\n" + "="*20 + " KẾT QUẢ " + "="*20)
        # In ra dữ liệu đã giải nén
        print(decompressed_data.decode('utf-8', errors='ignore'))
        print("="*48 + "\n")

    except zlib.error as e:
        print(f"[!] Lỗi khi giải nén zlib: {e}")
    except Exception as e:
        print(f"[!] Lỗi không xác định khi xử lý dữ liệu: {e}")

# Chạy hàm giải
if __name__ == '__main__':
    solve_6pack_final()