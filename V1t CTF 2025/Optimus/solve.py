def is_prime(n):
    """Hàm kiểm tra số nguyên tố được dịch từ C."""
    if n < 2:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False
    i = 3
    while i * i <= n:
        if n % i == 0:
            return False
        i += 2
    return True

# Chuỗi lộn xộn từ mã giả
scrambled_string = "0ov13tc{9zxpdr6na13m6a73534th5a}"

# Chuỗi để xây dựng flag
flag = ""

# Lặp qua từng chỉ số của chuỗi lộn xộn
for i in range(len(scrambled_string)):
    # Nếu chỉ số là một số nguyên tố
    if is_prime(i):
        # Nối ký tự tại chỉ số đó vào flag
        flag += scrambled_string[i]

# In ra flag cuối cùng
print(f"Flag: {flag}")