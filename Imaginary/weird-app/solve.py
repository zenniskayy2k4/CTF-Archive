def solve():
    ciphertext = "idvi+1{s6e3{)arg2zv[moqa905+"
    
    letters = "abcdefghijklmnopqrstuvwxyz"
    numbers = "0123456789"
    symbols = "!@#$%^&*()_+{}[]|"
    
    flag = ""
    
    for i, char in enumerate(ciphertext):
        if char in letters:
            new_index = letters.find(char)
            # old_index = (new_index - i) % len(letters)
            old_index = (new_index - i + len(letters)) % len(letters) # Cách an toàn để xử lý số âm
            flag += letters[old_index]
        elif char in numbers:
            new_index = numbers.find(char)
            # old_index = (new_index - i * 2) % len(numbers)
            old_index = (new_index - (i * 2) + len(numbers) * 100) % len(numbers) # Nhân với số lớn để đảm bảo dương
            flag += numbers[old_index]
        elif char in symbols:
            new_index = symbols.find(char)
            # old_index = (new_index - i * i) % len(symbols)
            old_index = (new_index - (i * i) + len(symbols) * 1000) % len(symbols)
            flag += symbols[old_index]
        else:
            # Nếu có ký tự không thuộc 3 nhóm trên (ít khả năng)
            flag += char
            
    return flag

final_flag = solve()
print(final_flag)