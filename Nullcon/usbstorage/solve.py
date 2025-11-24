import pcapy
import dpkt
import sys

def solve_usb_storage_raw(pcap_file, output_file):
    """
    Extracts data from USB mass storage traffic by analyzing raw packet data.
    This method is more robust against different tshark/scapy versions.
    """
    print(f"[*] Opening capture file: {pcap_file}")
    
    try:
        # Open the pcap file for reading
        pcap = pcapy.open_offline(pcap_file)
    except Exception as e:
        print(f"[!] Error opening pcap file: {e}")
        print("    Please make sure 'pcapy' is installed (`pip install pcapy`)")
        print("    You might also need to install libpcap development files.")
        print("    On Debian/Ubuntu: sudo apt-get install libpcap-dev")
        print("    On RedHat/CentOS: sudo yum install libpcap-devel")
        return

    all_data = b''
    packet_count = 0
    data_packet_count = 0

    print("[*] Processing packets...")

    # Loop through packets
    while True:
        try:
            header, packet = pcap.next()
            if not header:
                break
            
            packet_count += 1
            
            # This is specific to Linux USB captures (usbmon)
            # The header is 64 bytes. The first byte indicates the transfer type.
            # 0x02 = SUBMIT, 0x03 = COMPLETE
            # The direction is in byte 8: 0x80 for IN (Device to Host)
            
            # Let's check the packet structure based on common usbmon captures
            # A simple heuristic is to check the length. Data packets are usually large.
            if len(packet) > 100:
                # The actual USB data starts after a header (often 64 bytes for usbmon)
                # The first 31 bytes of the actual USB data is the SCSI wrapper.
                # So we skip 64 (pcap header) + 31 (SCSI wrapper) = 95 bytes
                # However, this can be tricky. Let's try to find a known pattern.
                
                # A more reliable way is to find the USB Mass Storage signature 'USBC'
                # This indicates the start of a Command Status Wrapper (CSW).
                # Data packets usually follow a Command Block Wrapper (CBW) starting with 'USBC'.
                # Let's just focus on packet size from device to host, as it's the most robust method.

                # Let's assume the first 64 bytes are the usbmon header.
                if len(packet) > 64:
                    usb_payload = packet[64:]
                    # The payload should start with 'USBS' for a status block or data
                    # Or it might be the raw data itself.
                    # Looking at your wireshark screenshot, the data packets are easily identifiable by length.
                    # Let's try to extract the payload directly based on length.
                    
                    # The length field in the URB header is at offset 24 (little-endian, 4 bytes)
                    # The direction is at offset 8 (0x80 for IN)
                    if len(packet) >= 32:
                        direction_byte = packet[8]
                        data_len = int.from_bytes(packet[24:28], byteorder='little')
                        
                        # We are looking for data coming IN to the host
                        if direction_byte == 0x80 and data_len > 0:
                            # The actual data starts after the 64-byte header
                            payload = packet[64:64 + data_len]
                            all_data += payload
                            data_packet_count += 1

        except pcapy.PcapError:
            # No more packets
            break

    if data_packet_count > 0:
        print(f"[+] Found and extracted data from {data_packet_count} packets.")
        print(f"[*] Writing {len(all_data)} bytes to '{output_file}'...")
        with open(output_file, 'wb') as f:
            f.write(all_data)
        print(f"[*] Successfully created '{output_file}'.")
        print("[*] Now run 'file recovered_file' to identify the file type.")
    else:
        print("[!] No matching USB data packets found. The capture format might be different.")

# --- MAIN EXECUTION ---
if __name__ == "__main__":
    if len(sys.argv) > 1:
        pcap_filename = sys.argv[1]
    else:
        pcap_filename = 'usbstorage.pcapng'

    output_filename = 'recovered_file_scapy'
        
    solve_usb_storage_raw(pcap_filename, output_filename)