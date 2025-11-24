import gdb
import sys

# Đảm bảo GDB đang sử dụng Python 3
if sys.version_info.major < 3:
    print("Script này yêu cầu Python 3.")
    gdb.execute("quit")

class FlagBuilder(gdb.Command):
    def __init__(self):
        super(FlagBuilder, self).__init__("solve", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        known_flag = ""
        total_len = 53
        breakpoint_addr = "*0x49e0b7"

        print(f"Bắt đầu quá trình xây dựng flag {total_len} ký tự...")

        # Vòng lặp chính: mỗi lần lặp tìm một ký tự mới
        for i in range(total_len):
            # 1. Chuẩn bị chuỗi đầu vào: phần đã biết + phần đệm
            padding = 'A' * (total_len - len(known_flag))
            current_input = known_flag + padding

            # 2. Đặt breakpoint và chạy chương trình với chuỗi đầu vào mới
            gdb.execute(f"b {breakpoint_addr}", to_string=True)
            run_command = f"run < <(python3 -c \"print('{current_input}')\")"
            gdb.execute(run_command, to_string=True)

            # 3. Bỏ qua các breakpoint cho các ký tự đã biết
            # Chúng ta cần hit breakpoint i+1 lần để đến ký tự chưa biết
            for _ in range(i):
                gdb.execute("continue", to_string=True)

            # 4. Bây giờ chương trình đang dừng ở breakpoint của ký tự chúng ta muốn tìm
            try:
                # Đọc các thanh ghi chứa tham số cho runtime.memequal
                rax_val = gdb.parse_and_eval("$rax")
                rbx_val = gdb.parse_and_eval("$rbx")

                # Đọc 1 byte từ mỗi địa chỉ mà thanh ghi trỏ tới
                char_a_bytes = gdb.selected_inferior().read_memory(rax_val, 1).tobytes()
                char_b_bytes = gdb.selected_inferior().read_memory(rbx_val, 1).tobytes()

                # Một trong hai sẽ là ký tự đệm 'A', cái còn lại là ký tự đúng
                new_char = ""
                if char_a_bytes == b'A':
                    new_char = char_b_bytes.decode('utf-8')
                else:
                    new_char = char_a_bytes.decode('utf-8')
                
                known_flag += new_char
                print(f"[{len(known_flag)}/{total_len}] Tìm thấy: '{new_char}'. Flag hiện tại: {known_flag}")

            except gdb.error as e:
                print(f"\nLỖI ở ký tự thứ {i+1}: {e}")
                print("Dừng quá trình.")
                break
        
        # Kết thúc vòng lặp
        print("\n=======================================================")
        if len(known_flag) == total_len:
            print(f"ĐÃ TÌM THẤY FLAG HOÀN CHỈNH: {known_flag}")
        else:
            print(f"Quá trình bị gián đoạn. Flag tìm được một phần: {known_flag}")
        print("=======================================================")
        
        # Xóa breakpoint và thoát
        gdb.execute("delete breakpoints", to_string=True)
        gdb.execute("quit")

FlagBuilder()