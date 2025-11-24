# Dữ liệu output từ chương trình
garbled_output = "94 7 d4 64 7 54 63 24 ad 98 45 72 35"
encrypted_bytes = [int(x, 16) for x in garbled_output.split()]

# 1. Các hàm ngược (không thay đổi)
def off_inv(n):
    return (n - 0xf) & 0xFF

def eor_inv(n):
    return n ^ 0x69

def rtr_inv(n):
    # Rotate Left 1 bit for 8-bit number
    return ((n << 1) & 0xFF) | (n >> 7)

# Ánh xạ tên hàm sang hàm ngược tương ứng
inverse_functions = {
    'off': off_inv,
    'eor': eor_inv,
    'rtr': rtr_inv,
}

# 2. Các khối xử lý đã được sửa lại cho chính xác
operation_blocks = [
    ['off', 'eor', 'rtr'],      # char 0 -> '1'
    ['eor', 'eor', 'eor'],      # char 1 -> 'n'
    ['rtr', 'off', 'rtr'],      # char 2 -> '5'
    ['rtr', 'rtr', 'eor'],      # char 3 -> '4'
    ['eor', 'eor', 'eor'],      # char 4 -> 'n'
    ['rtr', 'off', 'rtr'],      # char 5 -> '3'
    ['rtr', 'eor', 'rtr'],      # char 6 -> '_'
    ['rtr', 'rtr', 'eor'],      # char 7 -> '5'
    ['rtr', 'off', 'eor'],      # char 8 -> 'k'
    ['eor', 'eor', 'rtr'],      # char 9 -> '1'
    ['off', 'off', 'rtr'],      # char 10 -> 'l'
    ['rtr', 'rtr', 'eor'],      # char 11 -> 'l'
    ['eor', 'off', 'rtr'],      # char 12 -> '2'
]

# 3. Quá trình giải mã (không thay đổi)
decrypted_flag = []
for i in range(len(encrypted_bytes)):
    current_val = encrypted_bytes[i]
    operations = operation_blocks[i]
    
    # Áp dụng các hàm ngược theo thứ tự ngược lại
    for op_name in reversed(operations):
        inv_func = inverse_functions[op_name]
        current_val = inv_func(current_val)
        
    decrypted_flag.append(chr(current_val))

# In kết quả
flag_content = "".join(decrypted_flag)

# Định dạng lại flag cuối cùng
final_flag = f"ictf{{{flag_content}}}"
print(f"Flag: {final_flag}")