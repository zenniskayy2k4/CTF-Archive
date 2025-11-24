def reverse_power_step(ct):
    """
    Thực hiện một bước giải mã ngược lại với hàm power().
    Phép toán mã hóa là C = (3 * P) mod 26.
    Phép toán giải mã là P = (9 * C) mod 26.
    """
    res = ""
    # Nghịch đảo nhân của 3 trong modulo 26 là 9.
    MOD_INV_3 = 9
    
    for char in ct:
        # Giữ nguyên các ký tự đặc biệt trong format của flag
        if char in "LITCTF{_}":
            res += char
            continue
        
        # Chuyển ký tự ciphertext thành số (0-25)
        c_num = ord(char) - ord('a')
        
        # Áp dụng phép toán giải mã
        p_num = (c_num * MOD_INV_3) % 26
        
        # Chuyển số kết quả về lại ký tự
        res += chr(p_num + ord('a'))
        
    return res

# Ciphertext được cho trong hint
encrypted_flag = "LITCTF{fkxlafg_plk_qkuxbkgp_hucknkxk_khkx}"
num_iterations = 2345

print(f"Ciphertext ban đầu: {encrypted_flag}")

# Gán trạng thái hiện tại là ciphertext
current_state = encrypted_flag

# Lặp lại quá trình giải mã 2345 lần
for i in range(num_iterations):
    current_state = reverse_power_step(current_state)
    # Bạn có thể bỏ comment dòng dưới để xem quá trình giải mã
    # if (i + 1) % 100 == 0:
    #     print(f"Sau vòng {i+1}: {current_state}")

# Kết quả cuối cùng chính là flag
flag = current_state

print("\n-------------------------------------------")
print(f"Flag sau khi giải mã {num_iterations} lần: {flag}")
print("-------------------------------------------")