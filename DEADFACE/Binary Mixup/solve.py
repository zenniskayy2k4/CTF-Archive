binary_data = """
0011 0100
0011 0011
0010 0110
0101 0001
0001 0010
0010 0011
0100 0011
0100 0001
0011 0110
0011 0011
0001 0011
0010 0101
0100 0001
0101 0011
"""

# Tách thành các dòng
lines = binary_data.strip().split('\n')

# Tách thành hai cột nibbles
left_nibbles = []
right_nibbles = []
for line in lines:
    parts = line.split(' ')
    left_nibbles.append(parts[0])
    right_nibbles.append(parts[1])

# Ghép các nibble của cột phải lại với nhau
right_binary_string = "".join(right_nibbles)

# Chuyển chuỗi nhị phân dài thành văn bản
flag_text = ""
# Lặp qua chuỗi, mỗi lần lấy 8 ký tự (1 byte)
for i in range(0, len(right_binary_string), 8):
    byte = right_binary_string[i:i+8]
    # Chuyển byte nhị phân sang số nguyên, rồi sang ký tự ASCII
    decimal_value = int(byte, 2)
    flag_text += chr(decimal_value)

print(f"Chuỗi giải mã được từ cột phải: {flag_text}")

# Suy ra flag cuối cùng từ chuỗi đã giải mã
# Ký tự cuối cùng là ký tự không in được nên ta sẽ bỏ qua nó.
final_flag_content = "Ca#1c5" 
# Hoặc có thể là Cah1c5, tùy thuộc vào cách diễn giải, nhưng Ca#1c5 là kết quả trực tiếp.

print(f"Nội dung flag có khả năng nhất: {final_flag_content}")
print(f"Flag cuối cùng: deadface{{{final_flag_content}}}")