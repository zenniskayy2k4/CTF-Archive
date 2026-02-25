ho = [205, 196, 215, 218, 225, 226, 1189, 2045, 2372, 9300, 8304, 660, 8243, 16057, 16113, 16057, 16004, 16007, 16006, 8561, 805, 346, 195, 201, 154, 146, 223]

# Chúng ta biết chắc chắn flag bắt đầu bằng 'l'
flag = ['l']

for i in range(len(ho)):
    # Biểu thức gốc: ord(guess[i]) + ord(guess[i+1]) == ho[i]
    # Suy ra: ord(guess[i+1]) = ho[i] - ord(guess[i])
    
    current_char_code = ord(flag[i])
    next_char_code = ho[i] - current_char_code
    flag.append(chr(next_char_code))

print("Flag:", "".join(flag))