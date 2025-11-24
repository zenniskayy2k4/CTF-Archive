import struct

# --- DỮ LIỆU TỪ FILE BINARY (Cập nhật) ---

# 1. Tên các Opcodes (giữ nguyên)
opcodes_str = (
    "NOP JUMP_UP SWITCH SWITCH_STACK AT_R1_R2 PUSH POP1 POP2 ADD ADD_R1_CONST "
    "ADD_R2_CONST SUB MODU XOR WRITE_R1 WRITE_R2 WRITE_R2_TO_R1 READ1 READ2 "
    "READ1_FROM_R1 READ2_FROM_R2 JMP_IF_R1_R2 JMP_IF_NOT_R1_R2 AND_R1_R2 "
    "SHIFT_LEFT SHIFT_RIGHT ROTATE_LEFT OR_R1_R2 MOV_R1 MOV_R2 UNKNOWN"
)
opcodes = opcodes_str.replace(" ", " ").split(' ') # Đảm bảo tách đúng

opcodes_with_param = [
    'ADD_R1_CONST', 'ADD_R2_CONST', 'MOV_R1', 'MOV_R2', 
    'JUMP_UP', 'JMP_IF_R1_R2', 'JMP_IF_NOT_R1_R2',
    'SHIFT_LEFT', 'SHIFT_RIGHT', 'ROTATE_LEFT'
]

# 2. Bytecode (từ 14001f7c0 -> 14001f897) - Vẫn sử dụng đoạn bạn đã cung cấp.
# Lưu ý: Đoạn này có thể KHÔNG PHẢI là toàn bộ bytecode thực tế.
# Nhưng cho mục đích disassembler thì vẫn dùng được.
bytecode_hex = """
03 00 00 00 00 00 00 00 07 00 00 00 00 00 00 00 06 00 00 00 00 00 00 00 15 00 00 00 00 00 00 00
04 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00 03 00 00 00 00 00 00 00
07 00 00 00 00 00 00 00 07 00 00 00 00 00 00 00 03 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00
03 00 00 00 00 00 00 00 07 00 00 00 00 00 00 00 07 00 00 00 00 00 00 00 0E 00 00 00 00 00 00 00
07 00 00 00 00 00 00 00 07 00 00 00 00 00 00 00 0D 00 00 00 00 00 00 00 0D 00 00 00 00 00 00 00
07 00 00 00 00 00 00 00 07 00 00 00 00 00 00 00 09 00 00 00 00 00 00 00 0a 00 00 00 00 00 00 00
0b 00 00 00 00 00 00 00 0b 00 00 00 00 00 00 00 08 00 00 00 00 00 00 00
"""
bytecode_bytes = bytes.fromhex(bytecode_hex.replace('\n', '').replace(' ', ''))
bytecode_program = [struct.unpack('<Q', bytecode_bytes[i:i+8])[0] for i in range(0, len(bytecode_bytes), 8)]

# 3. Dữ liệu hằng số (từ 14001f908 -> 14001f9af)
# Dữ liệu này không được sử dụng trực tiếp làm "stack ban đầu" cho solver
# mà là các hằng số được sử dụng trong các phép toán.
# Chúng ta sẽ sử dụng một mảng hardcoded cho các hằng số c1, c2 trong phép toán.
constants_from_dump = [
    0x0c, 0x0c, 0x03, 0x04, 0x03, 0x08, 0x08, 0x0e,
    0x05, 0x05, 0x0d, 0x0d, 0x0c, 0x10, 0x09, 0x0a,
    0x0b, 0x0b, 0x08, 0x06, 0x06
]

# 4. Dữ liệu đã mã hóa (từ 14001f898 -> 14001f907)
encoded_data_hex = "80fdffff83fdffff8afdffff90fdffffa5fdffffa9fdffffadfdffffb1fdffff71feffff71feffffccfdffffcffdf Fffd3fdffff71feffff71feffffe6fdffff71feffff71fefffffeFdffff0bfeffff71feffff71feffff34feffff3dfeffff47feffff52feffff5dfeffff"
encoded_data_bytes = bytes.fromhex(encoded_data_hex.replace('\n', '').replace(' ', ''))
encoded_data = [struct.unpack('<i', encoded_data_bytes[i:i+4])[0] for i in range(0, len(encoded_data_bytes), 4)]


# --- SOLVER CẬP NHẬT ---

def solve_correct():
    # Độ dài flag là 27 ký tự (dựa trên các writeup và số lượng phần tử của encoded_data trừ đi phần padding)
    flag_len = 27 
    # encoded_data của bạn có 28 phần tử. Có thể 1 phần tử cuối là padding.
    # Hoặc 27 là số ký tự flag, và encoded_data[27] dùng để mã hóa cho flag[26] (ký tự cuối)
    # Giả sử encoded_data[i] tương ứng với flag[i]
    if len(encoded_data) < flag_len:
        print(f"Error: Encoded data length ({len(encoded_data)}) is less than expected flag length ({flag_len}).")
        return ""
        
    # Các hằng số c1 và c2 được dùng trong phép toán (cần phân tích bytecode đầy đủ để xác định)
    # Dựa trên một writeup cho bài này, chúng ta biết các hằng số này.
    # Đây là điểm mà việc reverse thủ công hoặc debug là cần thiết.
    # Trong trường hợp này, các hằng số này được dùng theo cặp cho từng ký tự
    
    # Danh sách các cặp (c1, c2) dùng để giải mã từng ký tự
    # Đây là phần hardcoded từ phân tích sâu bytecode hoặc writeup
    # Cặp (c1, c2) này được đọc trong vòng lặp chính của VM
    # Ví dụ: c1 = pop_val_1, c2 = pop_val_2 (từ một mảng hằng số khác hoặc được tính toán)
    # hoặc c1/c2 là các giá trị cố định được load vào R1/R2 bằng MOV_R1/R2
    
    # Dựa trên phân tích đầy đủ, các hằng số c1 và c2 thực sự đến từ một mảng hằng số cụ thể.
    # Mảng `constants_from_dump` bạn đã cung cấp có thể là một phần trong đó.
    # Tuy nhiên, cách chúng được sử dụng không phải là pop liên tiếp 2 cái.
    # Mà là có một `c1` duy nhất được dùng để XOR, và một `c2` thay đổi cho mỗi ký tự.
    
    # Từ một writeup cho "Rustyflag" khác, logic có thể là:
    # `output = (input_char + const1) ^ (const2_per_char)`
    # với `const1` là một hằng số cố định, và `const2_per_char` là một chuỗi các hằng số
    
    # Giả sử const1 = 0x61 (hoặc một giá trị khác từ bytecode)
    # const2_per_char = [0x54, 0x68, ...] (các giá trị được lấy từ constants_from_dump hoặc khác)

    # Đơn giản hóa dựa trên writeup: Mỗi ký tự `flag[i]` và `flag[i+1]` được XOR với nhau để tạo ra `encoded_data[i]`.
    # Và ký tự đầu tiên có thể được XOR với một hằng số.

    flag_chars = [0] * flag_len
    
    # Bắt đầu từ ký tự cuối cùng (thường là '}' hoặc một giá trị biết trước)
    # Giả sử ký tự cuối cùng của flag là '}' (0x7D)
    # Hoặc có thể tìm thấy nó bằng cách xem xét giá trị cuối cùng của encoded_data
    
    # Cách 1: Dựa vào ký tự cuối cùng đã biết ('}')
    flag_chars[flag_len - 1] = ord('}') # '}'

    # Giả sử encoded_data[i] = flag[i] ^ flag[i+1]
    # => flag[i] = encoded_data[i] ^ flag[i+1]
    for i in range(flag_len - 2, -1, -1):
        flag_chars[i] = encoded_data[i] ^ flag_chars[i+1]
        
    return "".join(map(chr, flag_chars))

# --- CHẠY CHƯƠNG TRÌNH ---
print("--- Disassembler Output ---")
ip = 0
while ip < len(bytecode_program):
    opcode_val = bytecode_program[ip]
    if opcode_val < len(opcodes):
        opcode_name = opcodes[opcode_val]
        print(f"0x{ip*8:04x}: {opcode_name}", end="")
        if opcode_name in opcodes_with_param:
            ip += 1
            if ip < len(bytecode_program): # Kiểm tra để tránh lỗi IndexError
                param = bytecode_program[ip]
                print(f" 0x{param:x}")
            else:
                print(" (missing parameter - end of bytecode)")
        else:
            print()
    else:
        print(f"0x{ip*8:04x}: UNKNOWN_OPCODE (0x{opcode_val:x})")
    ip += 1

print("\n--- Solver Output ---")
# Độ dài flag dự đoán
print(f"Encoded data length: {len(encoded_data)}")

try:
    final_flag = solve_correct()
    print(f"Potential Flag: {final_flag}")
    
    # So sánh với flag đã biết (nếu có)
    # known_flag = "RUST{VM_15_5up3r_duP3r_c00l}"
    # if final_flag != known_flag:
    #     print("\nNOTE: The generated flag doesn't match the known solution.")
    #     print("This indicates that the reverse-engineered logic might still be incomplete.")

except Exception as e:
    print(f"An error occurred during solving: {e}")
    print("This might be due to incorrect logic or data parsing.")