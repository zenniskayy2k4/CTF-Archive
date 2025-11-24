# Dữ liệu trích xuất từ file CHAL.COM
key = b"BENC!*5"
target = bytes([0xa9, 0x11, 0xe3, 0x6f, 0x17, 0x79, 0x11])

# Chuyển key thành một list các số để có thể thay đổi (mutable)
shuffled_key = list(key)
n = len(shuffled_key)

# Giả định giá trị khởi tạo của thanh ghi AX (uVar2) là 0
ax = 0

# Vòng lặp chính mô phỏng lại thuật toán xáo trộn
# Thanh ghi CX (in_CX) sẽ chạy từ n-1 (6) xuống 0
for i in range(n - 1, -1, -1):
    # Dựa theo code decompile của Ghidra
    # uVar2 = uVar2 ^ 0xb400;
    temp_ax = ax ^ 0xb400
    
    # *(uint *)0x256 = uVar2;
    state_var = temp_ax
    
    # j = state_var % (i + 1)
    # Đây là chỉ số thứ hai để hoán đổi
    j = state_var % (i + 1)
    
    # Hoán đổi hai ký tự: shuffled_key[i] và shuffled_key[j]
    shuffled_key[i], shuffled_key[j] = shuffled_key[j], shuffled_key[i]
    
    # uVar2 = *(uint *)0x256 >> 1;
    # Cập nhật lại ax cho vòng lặp tiếp theo
    ax = state_var >> 1

# Chuyển shuffled_key lại thành dạng bytes
final_shuffled_key = bytes(shuffled_key)

# Bây giờ, đảo ngược phép XOR cuối cùng để tìm ra mật khẩu
# password[i] = target[i] ^ final_shuffled_key[i]
password = bytes([t ^ s for t, s in zip(target, final_shuffled_key)])

print(f"Key ban đầu      : {key}")
print(f"Key sau khi xáo trộn: {final_shuffled_key}")
print(f"Dữ liệu mục tiêu : {target.hex()}")
print("-" * 30)
print(f"Mật khẩu cần tìm  : {password.decode('ascii')}")