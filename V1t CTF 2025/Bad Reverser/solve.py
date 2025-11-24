def solve_vm_reverse():
    """
    Hàm này giải bài CTF reverse bằng cách mô phỏng lại máy ảo (VM)
    để tái tạo lại flag từ bytecode được mã hóa.
    """
    # 1. Dữ liệu bytecode được mã hóa, trích xuất từ file binary tại địa chỉ 0x102040
    encrypted_bytecode = bytes([
        0x8c, 0xd1, 0x8f, 0x8e, 0x8d, 0x8c, 0xc7, 0x8f, 0x8e, 0x8c, 0x8c, 0xd3,
        0x8f, 0x8e, 0x8f, 0x8c, 0xf5, 0x8f, 0x8e, 0x8e, 0x8c, 0xc8, 0x8f, 0x8e,
        0x89, 0x8c, 0x9e, 0x8f, 0x8e, 0x88, 0x8c, 0xee, 0x8f, 0x8e, 0x8b, 0x8c,
        0xd7, 0x8f, 0x8e, 0x8a, 0x72
    ])

    # 2. Tính toán key giải mã dựa trên ký tự đầu tiên của flag ('v')
    # Key này cũng được VM sử dụng cho lệnh XOR.
    # (ord('v') + 7) ^ 0x5a  == (0x76 + 7) ^ 0x5a == 0x7d ^ 0x5a == 0x27
    decryption_key = 0x27

    # 3. Giải mã toàn bộ bytecode
    bytecode = bytearray(byte ^ decryption_key ^ 0xaa for byte in encrypted_bytecode)

    # 4. Mô phỏng máy ảo để xây dựng lại flag
    stack = []
    flag = [''] * 11  # Khởi tạo một mảng rỗng 11 ký tự cho flag
    
    ip = 0  # Instruction Pointer - Con trỏ lệnh
    while ip < len(bytecode):
        opcode = bytecode[ip]

        if opcode == 1:  # PUSH
            ip += 1
            value = bytecode[ip]
            stack.append(value)
        
        elif opcode == 2:  # XOR
            value_from_stack = stack.pop()
            xored_value = value_from_stack ^ decryption_key
            stack.append(xored_value)

        elif opcode == 3:  # CHECK
            ip += 1
            flag_index = bytecode[ip]
            # Giá trị trên đỉnh stack chính là mã ASCII của ký tự đúng
            correct_char_code = stack.pop()
            flag[flag_index] = chr(correct_char_code)
        
        elif opcode == 0xff: # HALT
            break
            
        ip += 1

    # 5. In ra kết quả cuối cùng
    final_flag = "".join(flag)
    print(f"Flag: v1t{final_flag}")

# Chạy hàm giải
solve_vm_reverse()