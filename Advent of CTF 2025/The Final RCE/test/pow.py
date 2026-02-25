def solve_pow(p):
    """
    Tự động đọc challenge và chạy lệnh solver
    """
    try:
        p.recvuntil(b'proof of work:\n')
        # Đọc dòng lệnh server yêu cầu: curl ... | sh -s ...
        cmd = p.recvline().strip().decode()
        log.info(f"Solving PoW: {cmd}")
        
        # Chạy lệnh trong shell cục bộ để tính toán
        # Lưu ý: Yêu cầu máy bạn có curl và kết nối internet
        result = subprocess.check_output(cmd, shell=True).strip()
        
        log.success(f"PoW Solution: {result.decode()}")
        p.sendlineafter(b'solution: ', result)
    except Exception as e:
        log.warning(f"PoW Step failed or skipped: {e}")