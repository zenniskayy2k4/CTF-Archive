from scapy.all import rdpcap

pcap_file = 'traffic.pcap'
try:
    packets = rdpcap(pcap_file)
    binary_string = ""

    syn_packets = [p for p in packets if p.haslayer('TCP') and p['TCP'].flags == 'S']

    for packet in syn_packets:
        if packet.haslayer('IP'):
            dst_ip = packet['IP'].dst
            
            # ===== THAY ĐỔI Ở ĐÂY =====
            if dst_ip == "10.0.0.2":
                binary_string += "1"  # Gán là 1
            elif dst_ip == "10.0.0.3":
                binary_string += "0"  # Gán là 0
            # =========================
            
    print(f"Chuỗi nhị phân đã trích xuất: {binary_string}")

    flag = ""
    if binary_string:
        try:
            byte_chunks = [binary_string[i:i+8] for i in range(0, len(binary_string), 8)]
            for chunk in byte_chunks:
                if len(chunk) == 8:
                    flag += chr(int(chunk, 2))
            
            print(f"\nFlag là: {flag}")

        except Exception as e:
            print(f"\nKhông thể giải mã chuỗi nhị phân: {e}")
    else:
        print("\nKhông trích xuất được chuỗi nhị phân nào.")

except Exception as e:
    print(f"Lỗi khi đọc file pcap: {e}")