from pwn import *

# --- Cấu hình ---
HOST = '94.237.48.60'
PORT = 58126
# Đặt timeout để tránh script bị treo
context.timeout = 5 # giây
# -------------------

def solve():
    """
    Kết nối đến server và lấy flag từng ký tự một.
    """
    flag = ""
    index = 0
    
    # Kết nối đến server
    log.info(f"Đang kết nối đến {HOST}:{PORT}")
    p = remote(HOST, PORT)

    while True:
        try:
            # Đợi server gửi prompt
            p.recvuntil(b'Enter an index: ')

            # Gửi index hiện tại mà chúng ta muốn truy vấn
            log.info(f"Đang truy vấn index {index}...")
            p.sendline(str(index).encode())

            # Đọc phản hồi của server. Phản hồi nằm giữa index ta gửi và prompt tiếp theo.
            # Chúng ta sẽ đọc cho đến prompt tiếp theo và loại bỏ nó.
            response_line = p.recvuntil(b'Which character', drop=True).decode().strip()
            
            # --- Xử lý ký tự ---
            # Phần này có thể cần điều chỉnh tùy thuộc vào output chính xác của server.
            # Giả định rằng ký tự flag là phần cuối cùng của dòng phản hồi.
            # Ví dụ: "The character is: H" -> ta sẽ lấy "H"
            char = response_line.split(':')[-1].strip()

            # Dọn dẹp các dấu nháy đơn/kép có thể có
            char = char.replace("'", "").replace('"', '')
            # -----------------------------

            # Kiểm tra xem có lấy được ký tự hợp lệ không
            if not char or len(char) != 1:
                log.error(f"Không thể trích xuất ký tự từ phản hồi: '{response_line}'")
                break

            # Thêm ký tự tìm được vào flag
            flag += char
            log.success(f"Flag hiện tại: {flag}")

            # Nếu tìm thấy dấu '}', chúng ta đã hoàn thành!
            if char == '}':
                log.success("Đã tìm thấy ký tự cuối của flag!")
                break
            
            # Chuyển sang index tiếp theo
            index += 1

        except EOFError:
            log.error("Kết nối đã bị server đóng.")
            break
        except Exception as e:
            log.error(f"Đã xảy ra lỗi: {e}")
            break

    # Đóng kết nối
    p.close()
    return flag

if __name__ == "__main__":
    final_flag = solve()
    print("\n" + "="*40)
    print(f"  Flag cuối cùng: {final_flag}")
    print("="*40)
    
# Flag: HTB{tH15_1s_4_r3aLly_l0nG_fL4g_i_h0p3_f0r_y0Ur_s4k3_tH4t_y0U_sCr1pTEd_tH1s_oR_els3_iT_t0oK_qU1t3_l0ng!!}