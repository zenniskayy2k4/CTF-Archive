import sys

def str_shuffle_with_precomputed_rand(s, rand_sequence):
    """Xáo trộn chuỗi sử dụng một chuỗi số ngẫu nhiên đã được tính toán trước."""
    char_list = list(s)
    n = len(char_list)
    
    if len(rand_sequence) != n - 1:
        raise ValueError("Độ dài chuỗi số ngẫu nhiên không khớp với độ dài chuỗi ký tự.")
        
    # Thực hiện thuật toán Fisher-Yates với các chỉ số đã cho
    for k, i in enumerate(range(n - 1, 0, -1)):
        j = rand_sequence[k]
        # Hoán vị
        char_list[i], char_list[j] = char_list[j], char_list[i]
        
    return "".join(char_list)


# --- PHẦN CHÍNH CỦA SCRIPT ---

# 1. Dán mật khẩu bạn nhận được từ server vào đây (bạn đã làm đúng)
first_shuffled_password = "7F6_23Ha8:5E4N3_/e27833D4S5cNaT_1i_O46STLf3r-4AH6133bdTO5p419U0n53Rdc80F4_Lb6_65BSeWb38f86{dGTf4}eE8__SW4Dp86_4f1VNH8H_C10e7L62154"

# 2. DÁN CHUỖI SỐ DÀI MÀ BẠN LẤY ĐƯỢC TỪ PHP ONLINE VÀO ĐÂY
php_rand_sequence_str = "93,92,19,108,67,15,87,113,111,116,28,9,21,71,55,4,6,107,19,90,38,82,74,57,34,87,50,30,42,54,85,16,85,93,74,93,20,47,28,3,42,4,57,38,33,76,18,69,23,39,71,33,22,4,23,52,64,56,13,65,23,55,66,37,4,19,60,30,12,50,33,13,13,56,2,26,19,9,7,32,27,15,11,25,40,30,8,5,16,19,24,15,34,3,3,27,7,19,29,8,22,25,9,26,10,6,16,22,13,5,11,18,6,11,6,7,1,1,0,10,1,2,4,2,1,1,3,0,1"

# Kiểm tra xem bạn đã dán chuỗi số chưa
if php_rand_sequence_str == "PASTE_PHP_RANDOM_NUMBERS_HERE":
    print("!!! LỖI: Bạn chưa dán chuỗi số ngẫu nhiên từ PHP vào script.")
    sys.exit(1)

# Chuyển chuỗi số thành một list các số nguyên
try:
    php_rand_sequence = [int(n) for n in php_rand_sequence_str.split(',')]
except ValueError:
    print("!!! LỖI: Chuỗi số ngẫu nhiên không hợp lệ. Hãy kiểm tra lại.")
    sys.exit(1)
    
current_password = first_shuffled_password
previous_password = ""
count = 0

print(f"[*] Bắt đầu tấn công với mật khẩu: {current_password}")
print("[*] Đang tìm chu trình với chuỗi số ngẫu nhiên chuẩn...")

while True:
    previous_password = current_password
    
    # Sử dụng hàm shuffle mới, đáng tin cậy 100%
    current_password = str_shuffle_with_precomputed_rand(current_password, php_rand_sequence)
    
    count += 1
    
    if current_password == first_shuffled_password:
        print(f"\n[+] Đã tìm thấy chu trình sau {count} lần hoán vị.")
        flag = previous_password
        break

print(f"\n[+] FLAG GỐC LÀ: {flag}")