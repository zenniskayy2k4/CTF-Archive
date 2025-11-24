from typing import List
import random
import math # Để dùng gcd

# Các hàm này cần được định nghĩa nếu bạn muốn test lại ở cuối
# def get_permutation(n : int) -> List[int]: ...
# def compose_permutation(p1 : List[int], p2 : List[int]): ...
# def permutation_power(p : List[int], n : int) -> List[int]: ...

# --- Các hàm tự viết ---
def get_cycles(p_list: List[int]) -> List[List[int]]:
    n_len = len(p_list)
    visited_nodes = [False] * n_len
    all_cycles = []
    for i in range(n_len):
        if not visited_nodes[i]:
            current_node_in_cycle = i
            one_cycle = []
            while not visited_nodes[current_node_in_cycle]:
                visited_nodes[current_node_in_cycle] = True
                one_cycle.append(current_node_in_cycle)
                current_node_in_cycle = p_list[current_node_in_cycle]
            if one_cycle: 
                all_cycles.append(one_cycle)
    return all_cycles

def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    d, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return d, x, y

def mod_inverse(a, m):
    if m == 1: return 0 # Inverse mod 1 is typically 0 or undefined
    d, x, y = extended_gcd(a, m)
    if d != 1:
        raise ValueError(f"Modular inverse does not exist for {a} mod {m} (gcd={d})")
    return (x % m + m) % m

def solve_crt(remainders_list, moduli_list):
    if not remainders_list or not moduli_list:
        return 0, 1 

    current_rem = remainders_list[0]
    current_mod = moduli_list[0]
    if current_mod == 0 : # Không nên xảy ra với độ dài chu trình
        raise ValueError("Modulus không thể bằng 0 trong CRT")
    if current_mod == 1: # Nếu modulus đầu tiên là 1, khởi tạo lại
        current_rem = 0 
        # Tìm modulus khác 1 đầu tiên
        found_valid_start = False
        for i in range(1, len(moduli_list)):
            if moduli_list[i] > 1:
                current_rem = remainders_list[i]
                current_mod = moduli_list[i]
                start_index = i + 1
                found_valid_start = True
                break
        if not found_valid_start and current_mod == 1 : # Tất cả moduli là 1
            return 0,1
        if not found_valid_start and current_mod !=1 : # Chỉ có 1 modulus ban đầu và nó >1
             start_index = 1 # Bắt đầu từ phần tử tiếp theo nếu có

    else: # current_mod ban đầu > 1
        start_index = 1


    for i in range(start_index, len(moduli_list)):
        next_rem = remainders_list[i]
        next_mod = moduli_list[i]

        if next_mod == 0: raise ValueError("Modulus không thể bằng 0 trong CRT")
        if next_mod == 1: continue # Bỏ qua phương trình x === r (mod 1)

        a = current_mod
        b = (next_rem - current_rem) % next_mod 
        m = next_mod
        
        g, x_bezout, y_bezout = extended_gcd(a, m)

        if b % g != 0:
            raise ValueError(f"Hệ phương trình CRT không có nghiệm (mâu thuẫn tại {current_rem} mod {current_mod} và {next_rem} mod {next_mod})")
            
        k_one_sol = ( (b // g) * x_bezout ) % (m // g) 

        current_rem = current_rem + k_one_sol * current_mod
        current_mod = (current_mod * next_mod) // g 
        current_rem %= current_mod 
        if current_rem < 0: current_rem += current_mod

    return current_rem, current_mod

# --- DỮ LIỆU TỪ SERVER ---
perm_val = [153, 17, 196, 503, 301, 309, 96, 388, 413, 287, 133, 474, 68, 272, 293, 132, 509, 206, 284, 300, 166, 138, 458, 404, 65, 312, 357, 250, 311, 443, 91, 205, 460, 265, 191, 379, 195, 434, 502, 157, 141, 490, 278, 459, 345, 161, 234, 80, 92, 462, 318, 144, 330, 159, 295, 62, 204, 308, 246, 297, 444, 453, 148, 328, 389, 399, 392, 21, 488, 121, 99, 340, 456, 420, 209, 244, 210, 268, 245, 358, 491, 126, 496, 475, 211, 31, 124, 400, 72, 150, 473, 105, 217, 94, 374, 438, 461, 249, 280, 331, 88, 8, 298, 175, 223, 18, 238, 349, 52, 290, 342, 465, 152, 172, 391, 131, 4, 225, 477, 471, 81, 2, 427, 361, 12, 48, 237, 422, 235, 362, 252, 449, 135, 341, 472, 429, 37, 27, 194, 302, 169, 398, 125, 50, 116, 190, 364, 501, 315, 484, 95, 482, 154, 251, 231, 75, 167, 350, 248, 493, 36, 51, 100, 332, 339, 108, 412, 24, 494, 316, 188, 60, 274, 143, 102, 486, 277, 450, 452, 182, 23, 351, 13, 410, 348, 310, 224, 264, 97, 83, 193, 495, 326, 215, 367, 69, 189, 3, 44, 385, 376, 418, 270, 419, 363, 259, 165, 396, 256, 253, 423, 98, 479, 299, 406, 320, 19, 306, 176, 64, 402, 160, 334, 478, 454, 122, 222, 368, 11, 510, 216, 424, 417, 16, 174, 507, 226, 435, 142, 322, 130, 63, 500, 397, 187, 440, 181, 158, 26, 307, 59, 487, 289, 87, 403, 303, 39, 85, 115, 387, 344, 218, 257, 41, 393, 291, 227, 168, 35, 283, 213, 178, 128, 386, 22, 232, 394, 378, 71, 114, 390, 254, 279, 447, 38, 177, 14, 118, 267, 314, 371, 421, 292, 464, 382, 451, 375, 426, 370, 262, 276, 409, 329, 34, 469, 9, 192, 286, 313, 137, 273, 20, 377, 369, 79, 229, 53, 319, 381, 511, 49, 113, 70, 499, 78, 185, 129, 170, 104, 123, 134, 86, 335, 470, 147, 504, 155, 343, 5, 324, 405, 214, 221, 383, 481, 136, 260, 241, 288, 468, 197, 233, 282, 373, 446, 67, 266, 10, 74, 432, 93, 489, 240, 162, 56, 202, 179, 0, 359, 304, 416, 327, 146, 437, 338, 42, 77, 127, 149, 29, 352, 47, 366, 7, 90, 73, 305, 401, 54, 25, 55, 346, 441, 255, 360, 430, 414, 372, 32, 347, 485, 411, 89, 317, 395, 271, 384, 476, 492, 439, 15, 163, 408, 156, 109, 455, 46, 120, 151, 285, 480, 212, 208, 66, 207, 258, 448, 337, 436, 45, 183, 40, 336, 198, 219, 323, 498, 139, 243, 505, 164, 228, 171, 242, 407, 467, 445, 28, 425, 261, 415, 107, 61, 380, 497, 6, 457, 106, 103, 325, 203, 508, 117, 230, 200, 111, 275, 466, 110, 33, 296, 82, 354, 84, 239, 43, 269, 186, 428, 145, 236, 220, 431, 506, 199, 281, 112, 76, 180, 201, 30, 119, 463, 483, 365, 356, 184, 58, 173, 353, 57, 433, 1, 442, 355, 294, 247, 333, 140, 101, 263, 321]
result_perm_val = [497, 506, 207, 433, 348, 283, 232, 319, 369, 14, 489, 156, 104, 262, 364, 381, 57, 247, 53, 3, 127, 477, 452, 436, 265, 199, 123, 311, 312, 457, 140, 475, 330, 326, 187, 72, 152, 176, 493, 222, 165, 461, 163, 371, 449, 119, 416, 383, 45, 209, 427, 82, 357, 323, 321, 285, 68, 125, 379, 166, 136, 194, 177, 145, 149, 291, 509, 118, 223, 231, 399, 335, 430, 137, 13, 368, 351, 100, 245, 179, 7, 390, 451, 109, 398, 83, 63, 235, 395, 474, 40, 169, 161, 444, 407, 322, 417, 243, 460, 347, 404, 313, 174, 453, 193, 316, 15, 274, 26, 220, 103, 465, 282, 405, 76, 216, 184, 87, 464, 54, 280, 424, 485, 105, 328, 429, 55, 420, 85, 301, 505, 19, 47, 201, 133, 80, 218, 28, 186, 490, 126, 108, 135, 122, 496, 289, 124, 425, 450, 374, 239, 1, 279, 58, 114, 227, 469, 334, 302, 499, 112, 471, 23, 273, 339, 248, 422, 33, 221, 237, 95, 345, 271, 225, 234, 380, 360, 445, 21, 213, 428, 443, 299, 50, 349, 188, 376, 432, 438, 414, 314, 264, 116, 79, 224, 154, 396, 501, 131, 5, 363, 38, 195, 472, 488, 43, 158, 260, 236, 272, 233, 32, 130, 121, 151, 358, 197, 51, 394, 378, 228, 486, 426, 215, 77, 400, 297, 34, 413, 455, 350, 391, 211, 500, 46, 31, 59, 62, 132, 24, 439, 479, 238, 99, 359, 440, 29, 139, 329, 397, 20, 246, 294, 128, 296, 75, 226, 189, 230, 459, 66, 276, 196, 96, 336, 129, 303, 342, 88, 64, 69, 67, 257, 249, 178, 84, 442, 93, 332, 487, 203, 470, 251, 389, 159, 446, 146, 293, 110, 382, 402, 362, 292, 56, 365, 113, 401, 412, 102, 2, 503, 288, 30, 244, 306, 286, 144, 372, 48, 447, 97, 377, 385, 92, 366, 415, 435, 42, 337, 278, 74, 340, 65, 315, 78, 170, 4, 150, 190, 91, 10, 241, 386, 259, 448, 305, 266, 254, 269, 324, 504, 418, 175, 403, 392, 261, 423, 212, 468, 22, 147, 242, 153, 510, 214, 287, 255, 361, 182, 495, 60, 18, 409, 180, 12, 36, 270, 454, 191, 217, 298, 89, 86, 263, 476, 411, 162, 73, 94, 456, 0, 343, 202, 317, 431, 309, 307, 325, 511, 484, 419, 210, 101, 155, 171, 173, 344, 331, 52, 421, 507, 185, 11, 375, 498, 355, 482, 434, 256, 267, 318, 310, 208, 304, 481, 466, 370, 98, 502, 354, 27, 240, 480, 16, 346, 463, 408, 281, 49, 491, 143, 206, 356, 115, 277, 148, 462, 41, 70, 168, 164, 8, 44, 106, 37, 384, 406, 25, 492, 300, 467, 172, 138, 367, 268, 275, 183, 410, 61, 327, 134, 120, 253, 157, 204, 111, 473, 90, 458, 192, 387, 295, 341, 141, 167, 290, 219, 200, 320, 252, 250, 441, 17, 373, 338, 333, 352, 181, 478, 284, 508, 388, 39, 353, 160, 393, 107, 35, 117, 229, 142, 258, 483, 198, 9, 494, 437, 205, 81, 308, 6, 71]
# --------------------------------------------------------------------

print(f"Hoán vị cơ sở (perm): {perm_val[:10]}... (dài {len(perm_val)})") # Rút gọn output
print(f"Hoán vị kết quả (result_perm): {result_perm_val[:10]}... (dài {len(result_perm_val)})")

if len(perm_val) != len(result_perm_val):
    print("Lỗi: Độ dài của perm và result_perm không khớp!")
    exit()

if len(perm_val) == 0:
    print("Lỗi: Hoán vị rỗng!")
    exit()
    
cycles = get_cycles(perm_val)
print(f"\nCác chu trình của perm (dài {len(cycles)} chu trình, hiển thị tối đa 5):")
for i, cycle in enumerate(cycles[:5]):
    print(f"  Chu trình {i+1} (dài {len(cycle)}): {cycle[:10]}{'...' if len(cycle)>10 else ''}")
if len(cycles) > 5: print("  ...")

remainders_for_crt = []
moduli_for_crt = []

unique_moduli_tracker = {} 

for cycle_idx, cycle in enumerate(cycles):
    L = len(cycle)
    if L == 1: 
        continue

    start_node = cycle[0]
    node_after_result = result_perm_val[start_node]

    try:
        k_L = cycle.index(node_after_result)
    except ValueError:
        print(f"!!! LỖI NGHIÊM TRỌNG trong chu trình {cycle_idx+1}: Phần tử {node_after_result} (kết quả của {start_node}) không tìm thấy trong chu trình {cycle}.")
        continue

    # print(f"Chu trình (dài {L}, bắt đầu {start_node}): {start_node} -> perm^flag -> {node_after_result}. Vị trí của {node_after_result} trong chu trình là {k_L}.")
    # print(f"  => flag === {k_L} (mod {L})")
    
    temp_L = L
    temp_k_L = k_L
    
    d = 2
    while d * d <= temp_L:
        if temp_L % d == 0:
            pk = d
            # Tìm d^a là ước của L, với a là lớn nhất
            # (Lưu ý: đoạn code gốc tìm pk = d, rồi while temp_L % (pk*d) == 0. Điều này sẽ làm pk tăng lên d, d^2, d^3,...
            # nhưng pk nên là d^current_power. Cách đúng hơn là chia L cho d nhiều lần)
            current_factor_power = d
            temp_L_for_factor = L # Sử dụng L gốc cho mỗi thừa số nguyên tố cơ sở
            
            # Xác định lũy thừa cao nhất của d mà là ước của L
            # Ví dụ L = 12, d = 2. pk_actual = 4.
            # L = 18, d = 3. pk_actual = 9.
            pk_actual = 1
            temp_L_copy = L
            while temp_L_copy > 0 and temp_L_copy % d == 0:
                pk_actual *= d
                temp_L_copy //= d
            # pk_actual bây giờ là d^a (lũy thừa cao nhất của d là ước của L)


            rem_pk = temp_k_L % pk_actual # flag === k_L (mod L) => flag === k_L (mod d^a)
            
            if pk_actual not in unique_moduli_tracker:
                unique_moduli_tracker[pk_actual] = rem_pk
                remainders_for_crt.append(rem_pk)
                moduli_for_crt.append(pk_actual)
                # print(f"    Thêm vào CRT: flag === {rem_pk} (mod {pk_actual}) từ L={L}, k_L={k_L}")
            elif unique_moduli_tracker[pk_actual] != rem_pk:
                print(f"!!! Mâu thuẫn CRT: Với mod {pk_actual} (từ L={L}, d={d}), đã có remainder {unique_moduli_tracker[pk_actual]}, giờ lại có {rem_pk} (từ k_L={k_L})")
            
            while temp_L % d == 0: 
                temp_L //= d
        d += 1
    if temp_L > 1: 
        pk_actual = temp_L # temp_L bây giờ là thừa số nguyên tố còn lại (hoặc 1)
        rem_pk = temp_k_L % pk_actual
        if pk_actual not in unique_moduli_tracker:
            unique_moduli_tracker[pk_actual] = rem_pk
            remainders_for_crt.append(rem_pk)
            moduli_for_crt.append(pk_actual)
            # print(f"    Thêm vào CRT: flag === {rem_pk} (mod {pk_actual}) từ L={L}, k_L={k_L} (thừa số cuối)")
        elif unique_moduli_tracker[pk_actual] != rem_pk:
             print(f"!!! Mâu thuẫn CRT: Với mod {pk_actual} (từ L={L}, thừa số cuối), đã có remainder {unique_moduli_tracker[pk_actual]}, giờ lại có {rem_pk} (từ k_L={k_L})")


if not remainders_for_crt:
    print("\nKhông có đủ thông tin từ các chu trình để giải CRT.")
    if len(perm_val) > 0 and perm_val == result_perm_val:
         print("Có thể flag = 1 nếu perm = result_perm và không phải identity.")
    exit()

print(f"\nHệ phương trình đồng dư cho CRT (sau khi phân rã và loại bỏ trùng lặp, có {len(remainders_for_crt)} phương trình):")
# Sắp xếp theo modulus để dễ nhìn
sorted_equations = sorted(zip(remainders_for_crt, moduli_for_crt), key=lambda item: item[1])
for r, m in sorted_equations[:10]: # In ra 10 phương trình đầu
    print(f"  flag === {r} (mod {m})")
if len(sorted_equations) > 10: print("  ...")

# Cập nhật lại list để đưa vào CRT theo thứ tự đã sắp xếp (không bắt buộc nhưng có thể ổn định hơn)
remainders_for_crt = [item[0] for item in sorted_equations]
moduli_for_crt = [item[1] for item in sorted_equations]


try:
    flag_solution, final_modulus = solve_crt(remainders_for_crt, moduli_for_crt)
    print(f"\nNghiệm tìm được từ CRT:")
    print(f"  flag === {flag_solution} (mod {final_modulus})")
    print(f"Giá trị flag (số nguyên) nhỏ nhất không âm là: {flag_solution}")
    print(f"Lưu ý: Flag thực sự có thể là flag_solution + k * final_modulus.")
    print(f"Trong CTF, thường flag_solution chính là giá trị cần tìm.")
    print(f"Giá trị final_modulus (bậc của hoán vị): {final_modulus}")
    print(f"Số bit của flag_solution: {flag_solution.bit_length()}")
    print(f"Số bit của final_modulus: {final_modulus.bit_length()}")

    # Chuyển flag_solution (số nguyên) trở lại thành bytes, rồi thành text
    if flag_solution == 0 and final_modulus == 1 and not remainders_for_crt : # Trường hợp không có thông tin
        print("\nKhông thể xác định flag do không có đủ phương trình đồng dư.")
    elif flag_solution < 0: # Không nên xảy ra nếu CRT đúng
        print(f"\nLỗi: flag_solution là số âm: {flag_solution}")
    else:
        # Ước lượng số byte cần thiết
        # Nếu flag_solution là 0, to_bytes sẽ cần length > 0
        if flag_solution == 0:
            # Nếu flag là 0, có thể nó là byte rỗng hoặc một byte 0.
            # Khó xác định độ dài nếu không có thông tin thêm.
            # Tuy nhiên, flag từ file thường không phải là 0.
            # Nếu nó là byte rỗng, thì int.from_bytes(b'', ...) sẽ lỗi.
            # Nếu nó là b'\x00', thì int.from_bytes(b'\x00',...) = 0
            print("\nFlag solution là 0. Không chắc chắn về cách chuyển đổi sang text.")
            print("Thử với độ dài 1 byte nếu là ký tự NUL: ", (0).to_bytes(1, 'big').decode('utf-8', errors='replace'))
        else:
            num_bytes_for_flag = (flag_solution.bit_length() + 7) // 8
            print(f"Số byte ước lượng cho flag: {num_bytes_for_flag}")
            
            try:
                flag_bytes_reconstructed = flag_solution.to_bytes(num_bytes_for_flag, byteorder='big', signed=False)
                print(f"Flag (dạng bytes): {flag_bytes_reconstructed}")
                
                # Thử decode với các encoding phổ biến
                encodings_to_try = ['utf-8', 'ascii', 'latin-1']
                decoded_successfully = False
                for enc in encodings_to_try:
                    try:
                        flag_text_reconstructed = flag_bytes_reconstructed.decode(enc)
                        print(f"FLAG TÌM ĐƯỢC (decode bằng {enc}): {flag_text_reconstructed}")
                        decoded_successfully = True
                        break # Dừng lại khi decode thành công
                    except UnicodeDecodeError:
                        print(f"  (Không thể decode bằng {enc})")
                
                if not decoded_successfully:
                    print("Không thể decode flag bytes bằng các encoding phổ biến.")
                    
            except OverflowError:
                print(f"Lỗi OverflowError khi chuyển {flag_solution} sang bytes với độ dài {num_bytes_for_flag}.")
                print("Điều này không nên xảy ra nếu num_bytes_for_flag được tính đúng.")
            except Exception as e_conv:
                print(f"Lỗi khi chuyển đổi flag sang text: {e_conv}")

except ValueError as e:
    print(f"\nLỗi khi giải CRT: {e}")
    print("Có thể do các phương trình mâu thuẫn với nhau, kiểm tra lại tính toán k_L hoặc input.")
except Exception as e_gen:
    print(f"\nLỗi không xác định khi giải CRT hoặc xử lý kết quả: {e_gen}")