def solve():
    # Khởi tạo vùng nhớ stack 128 byte trắng
    stack = bytearray(0x300) 
    
    # Mô phỏng các lệnh gán của chương trình (đúng thứ tự trong code)
    # Chúng ta gán vào offset tính từ local_278 (địa chỉ cơ sở)
    
    def write_mem(offset_from_278, value, size):
        b_val = value.to_bytes(size, 'little')
        for i in range(size):
            stack[offset_from_278 + i] = b_val[i]

    # Offset dựa trên tên biến local_XXX của Ghidra
    # local_278 là gốc (0), uStack_270 cách 8 byte, local_268 cách 16 byte...
    write_mem(0x40, 0x2d2e3632, 4)         # local_238
    write_mem(0, 0x711d243621213623, 8)    # local_278
    write_mem(0x08, 0x7316130d0c0d7477, 8) # uStack_270 (Ghi đè lên local_268 một phần)
    write_mem(0x44, 0x372f, 2)             # local_234
    write_mem(0x10, 0x3434331074342a14, 8) # local_268
    write_mem(0x18, 0x3417363f072b3536, 8) # uStack_260
    write_mem(0x46, 3, 1)                  # local_232
    write_mem(0x20, 0x27373476332a0236, 8) # local_258
    write_mem(0x28, 0xf362a300e043636, 8)  # uStack_250
    write_mem(0x30, 0x2606732a66657206, 8) # local_248
    write_mem(0x38, 0x14782e3632342e2a, 8) # uStack_240

    # Thuật toán XOR của bài
    bVar5 = 0x23
    xor_key = 0x42
    result = []
    
    for lVar4 in range(71):
        result.append(chr(bVar5 ^ xor_key))
        # Lấy byte tiếp theo từ địa chỉ (&local_278 + lVar4 + 1)
        bVar5 = stack[lVar4 + 1]
        
    full_str = "".join(result)
    print(f"Toàn bộ chuỗi giải mã: {full_str}")

solve()