#!/usr/bin/env python3
# extract_dns_exfil.py
import sys, struct, socket, io, re

def parse_pcap_for_domains(pcap_path):
    data = open(pcap_path,'rb').read()
    # skip global header (24 bytes)
    offset = 24
    domains = []
    pkt_index = 0
    while offset + 16 <= len(data):
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack_from('<IIII', data, offset)
        offset += 16
        pkt_data = data[offset:offset+incl_len]
        offset += incl_len
        pkt_index += 1
        # search for length-prefixed labels in packet bytes
        for i in range(len(pkt_data)-10):
            parts = []
            j = i
            valid = False
            for _ in range(20):
                if j >= len(pkt_data):
                    break
                l = pkt_data[j]
                if l == 0:
                    # end of name
                    valid = len(parts) >= 1
                    j += 1
                    break
                if l & 0xC0:
                    # pointer - not handling pointers here
                    break
                if l > 63 or j+1+l > len(pkt_data):
                    break
                label = pkt_data[j+1:j+1+l]
                # check printable
                if all(32 <= c < 127 for c in label):
                    parts.append(label.decode('utf-8', errors='ignore'))
                else:
                    break
                j = j + 1 + l
            if valid:
                domain = '.'.join(parts)
                # record (packet index, timestamp, domain)
                domains.append((pkt_index, ts_sec, domain))
    return domains

def extract_fragments(domains, target_suffix='hex.cloudflar3.com'):
    # filter and order by packet index then ts
    filtered = [(pi,ts,d) for (pi,ts,d) in domains if d.endswith(target_suffix) or ('.' + target_suffix) in d]
    filtered.sort(key=lambda x:(x[0], x[1]))
    # extract label directly before suffix and strip one-letter prefixes like p./f.
    frags = []
    prev = None
    for pi,ts,d in filtered:
        label = d.split('.' + target_suffix)[0]
        if label.startswith('p.') or label.startswith('f.'):
            label = label.split('.',1)[1]
        if label != prev:  # remove immediate duplicates (optional)
            frags.append((pi,ts,label))
            prev = label
    return frags

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: extract_dns_exfil.py capture.pcap")
        sys.exit(1)
    pcap = sys.argv[1]
    print("Parsing pcap:", pcap)
    domains = parse_pcap_for_domains(pcap)
    print("Total domain-like names found:", len(domains))
    frags = extract_fragments(domains)
    print("Fragments found (in order):", len(frags))
    for i,(pi,ts,lab) in enumerate(frags):
        print(i, ts, lab)
    # write hex file
    hex_concat = ''.join(lab for (_,_,lab) in frags)
    with open('exfil.hex','w') as fh:
        fh.write(hex_concat)
    try:
        b = bytes.fromhex(hex_concat)
        open('exfil.bin','wb').write(b)
        print("Wrote exfil.hex and exfil.bin (binary length: {})".format(len(b)))
    except Exception as e:
        print("Could not hex-decode concatenated fragments:", e)
        print("exfil.hex saved anyway; inspect fragments/ordering manually.")
