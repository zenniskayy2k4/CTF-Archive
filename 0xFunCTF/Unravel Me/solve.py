import angr
import claripy

# Thiết lập thông số
binary_path = "./crackme"
# Địa chỉ hàm chứa logic kiểm tra (thay vì entry point)
# Dựa trên code của bạn, hãy thử bắt đầu từ đầu hàm entry/main
start_addr = 0x08049273 # Đây là địa chỉ hàm chính bạn gửi ở trên
addr_correct = 0x08051612 
addr_wrong = 0x080517bf

project = angr.Project(binary_path, auto_load_libs=False)

# Flag thường bắt đầu bằng format của giải, ví dụ: "0xFun{"
# Giả sử flag dài 42 ký tự (số đẹp)
flag_length = 42 
flag_chars = [claripy.BVS(f"flag_{i}", 8) for i in range(flag_length)]
flag = claripy.Concat(*flag_chars)

# Khởi tạo state tại hàm logic để tránh anti-debug ở entry
state = project.factory.blank_state(addr=start_addr)

# Ràng buộc ký tự in được
for char in flag_chars:
    state.add_constraints(char >= 0x20, char <= 0x7e)

# Nếu biết chắc format flag, hãy ép nó vào để chạy nhanh hơn:
state.add_constraints(flag_chars[0] == ord('0'))
state.add_constraints(flag_chars[1] == ord('x'))

simgr = project.factory.simulation_manager(state)

print(f"[*] Đang càn quét từ {hex(start_addr)}... Hãy kiên nhẫn!")
simgr.explore(find=addr_correct, avoid=addr_wrong)

if simgr.found:
    print("[+] Tìm thấy đường đi!")
    sol = simgr.found[0].solver.eval(flag, cast_to=bytes)
    print(f"FLAG: {sol}")
else:
    print("[-] Vẫn không ra. Có thể logic nằm ở một thread khác hoặc dùng kĩ thuật anti-angr.")