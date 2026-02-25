from pwn import *
import math
import time
import re
from collections import defaultdict

context.log_level = 'info'

def get_pos(node_id):
    # Parse tọa độ 16-bit có dấu
    x = (node_id >> 16) & 0xFFFF
    y = node_id & 0xFFFF
    if x > 32767: x -= 65536
    if y > 32767: y -= 65536
    return x, y

def dist(id1, tx, ty):
    x1, y1 = get_pos(id1)
    return math.sqrt((x1 - tx)**2 + (y1 - ty)**2)

def solve():
    while True:
        try:
            print("[*] Connecting...")
            r = remote('ctf.csd.lol', 6969)
            break
        except:
            time.sleep(1)

    MAGIC = 0x53504d4b 

    def make_packet(cmd, payload=b''):
        total_len = 8 + len(payload)
        return p32(MAGIC) + p8(1) + p8(cmd) + p16(total_len) + payload

    # 2. Handshake
    r.send(make_packet(1))
    r.recvn(16)

    # 3. Lấy Target
    print("[*] Getting Target...")
    r.send(make_packet(4))
    
    header = r.recvn(8)
    msg_len = u16(header[6:8]) - 8
    msg = r.recvn(msg_len).replace(b'\x00', b'').decode(errors='ignore')
    
    match = re.search(r'0x([0-9a-fA-F]+)', msg)
    if match:
        TARGET_ID = int(match.group(1), 16)
        TX, TY = get_pos(TARGET_ID)
        print(f"[+] TARGET FOUND: {hex(TARGET_ID)} -> ({TX}, {TY})")
    else:
        print("[-] Target not found.")
        return

    # --- KHỞI TẠO BỘ NHỚ (Để chống lặp) ---
    visit_counts = defaultdict(int)
    step = 0

    # 4. Game Loop
    while True:
        try:
            # Gửi Cmd 2 (Lấy vị trí)
            r.send(make_packet(2))
            
            # Nhận Header
            header = r.recvn(8, timeout=5)
            if not header: break
            payload_len = u16(header[6:8]) - 8
            payload = r.recvn(payload_len)

            if b'csd{' in payload:
                print(f"\n[!!!] FLAG: {payload.decode(errors='ignore').strip()}\n")
                break

            # Parse State
            cur_id = u32(payload[0:4])
            count = u32(payload[4:8])
            
            # Đánh dấu đã đi qua điểm này
            visit_counts[cur_id] += 1
            
            cur_x, cur_y = get_pos(cur_id)
            distance = math.sqrt((cur_x - TX)**2 + (cur_y - TY)**2)
            
            step += 1
            # In ít lại cho đỡ lag console, chỉ in mỗi 10 bước hoặc khi rất gần
            if step % 10 == 0 or distance < 2000:
                print(f"Step {step}: At ({cur_x}, {cur_y}) | Dist: {distance:.2f} | Visited: {visit_counts[cur_id]} times")

            # Check Win
            if cur_id == TARGET_ID or distance == 0:
                print("[!] Reached Target! Sending Cmd 4...")
                r.send(make_packet(4))
                print(r.recvall(timeout=5).decode(errors='ignore'))
                break

            # --- THUẬT TOÁN THÔNG MINH HƠN ---
            neighbors_raw = payload[8:]
            best_node = -1
            best_score = float('inf') # Điểm càng thấp càng tốt

            for i in range(count):
                nid = u32(neighbors_raw[i*4 : (i+1)*4])
                
                # Tính khoảng cách thuần túy
                d = dist(nid, TX, TY)
                
                # Lấy số lần đã ghé thăm neighbor này
                v_count = visit_counts[nid]
                
                # Công thức điểm: Khoảng cách + (Số lần ghé * Phạt nặng)
                # Phạt 100,000m cho mỗi lần đã ghé.
                # Điều này khiến drone thà đi xa hơn 1 chút vào vùng đất mới
                # còn hơn là quay lại chỗ cũ.
                score = d + (v_count * 100000)
                
                if score < best_score:
                    best_score = score
                    best_node = nid

            if best_node == -1:
                print("[-] Stuck!")
                break

            # Gửi Move
            checksum = best_node ^ cur_id
            move_payload = p32(best_node) + p32(checksum)
            r.send(make_packet(3, move_payload))
            r.recvn(12) # Ack

        except Exception as e:
            print(f"[-] Error: {e}")
            break

if __name__ == "__main__":
    solve()