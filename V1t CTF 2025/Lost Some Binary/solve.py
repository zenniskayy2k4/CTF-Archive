# Chuỗi nhị phân được cung cấp
binary_string = "01001000 01101001 01101001 01101001 00100000 01101101 01100001 01101110 00101100 01101000 01101111 01110111 00100000 01110010 00100000 01110101 00100000 00111111 01001001 01110011 00100000 01101001 01110100 00100000 00111010 00101001 00101001 00101001 00101001 01010010 01100001 01110111 01110010 00101101 01011110 01011110 01011011 01011101 00100000 00100000 01001100 01010011 01000010 01111011 00111110 00111100 01111101 00100001 01001100 01010011 01000010 01111110 01111110 01001100 01010011 01000010 01111110 01111110 00101101 00101101 00101101 01110110 00110001 01110100 00100000 00100000 01111011 00110001 00110011 00110101 00111001 00110000 00110000 01011111 00110001 00110011 00110011 00110111 00110000 01111101"

# Tách chuỗi thành các byte
binary_values = binary_string.split(' ')

# Trích xuất LSB từ mỗi byte
lsb_string = ""
for byte in binary_values:
    lsb_string += byte[-1]

# Chuyển đổi chuỗi LSB thành văn bản
flag_string = ""
# Kiểm tra xem độ dài chuỗi có phải là bội số của 8 không
if len(lsb_string) % 8 == 0:
    # Lặp qua chuỗi LSB, mỗi lần 8 bit
    for i in range(0, len(lsb_string), 8):
        # Lấy ra một byte
        byte = lsb_string[i:i+8]
        # Chuyển đổi byte nhị phân thành số nguyên
        decimal_value = int(byte, 2)
        # Chuyển đổi số nguyên thành ký tự ASCII và nối vào flag
        flag_string += chr(decimal_value)

print(flag_string)