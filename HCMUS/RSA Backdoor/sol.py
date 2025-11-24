from Crypto.Util.number import getPrime, isPrime, bytes_to_long, long_to_bytes

# Giá trị từ output của challenge
n_val = 14072966033419198049110692513729221272039856578995770358978022374369702617407260974250371335874660886448635625415359435590866288684836396305467427652785918508438890316051644975416024575729239957690880362943383614229572482338338943926669325548496781092116918121854511282239218429506385724821682014631388855624828613598194700383
ct_val = 3297398274726419288742770485398984653524926733739942261260073512658711638212442235723491698663926587152143223728930627197111676440456437693388833394409296854208768556197435034647579096634751361373063515305871138820266505736702532043492078019209492809727200146481667680937461262102664960833393192739550652924626548337227957210
e_val = 65537

print(f"n = {n_val}")
print(f"ct = {ct_val}")
print(f"e = {e_val}")

# Bước 2: Tìm kiếm nhị phân cho p
# p là số 512-bit
low_p = 1 << 511  # 2**511
high_p = (1 << 512) - 1 # 2**512 - 1

p_solution = -1
q_solution = -1

print(f"Bắt đầu tìm kiếm nhị phân cho p trong khoảng [{low_p}, {high_p}]")

# Vòng lặp tìm kiếm nhị phân
# Tăng số lần lặp nếu cần, nhưng 512-600 thường là đủ cho không gian 512 bit
for _ in range(600): # Số lần lặp đủ để hội tụ cho không gian 512 bit
    if low_p > high_p:
        break
    
    mid_p = (low_p + high_p) // 2
    if mid_p == 0: # Phòng trường hợp khoảng bị thu hẹp không đúng cách
        # Thử dịch chuyển một chút nếu mid_p bằng 0, mặc dù không nên xảy ra với khoảng ban đầu
        if low_p > 0 : mid_p = low_p
        elif high_p > 0: mid_p = high_p
        else: break # Không thể tìm mid_p > 0

    try:
        # Tính q theo cách chuyển đổi từ p
        q_candidate_from_conversion = int(str(mid_p), 13)
    except ValueError: # Nếu str(mid_p) chứa ký tự không hợp lệ cho cơ số 13 (ví dụ 'a', 'b', 'c')
                       # Điều này không nên xảy ra vì str(p) chỉ có '0'-'9'
        print(f"Lỗi ValueError khi chuyển đổi str({mid_p}) sang cơ số 13. Bỏ qua.")
        # Xử lý lỗi này bằng cách điều chỉnh khoảng tìm kiếm, ví dụ:
        # Nếu lỗi, có thể mid_p quá lớn hoặc quá nhỏ khiến str() tạo ra thứ gì đó lạ.
        # Tuy nhiên, với số nguyên, str() luôn tạo ra chữ số 0-9.
        # Lỗi này KHÔNG nên xảy ra.
        high_p = mid_p -1 # Giả định mid_p quá lớn nếu có lỗi
        continue

    # Tính n ứng với mid_p và q_candidate_from_conversion
    # Cẩn thận với tràn số nếu mid_p và q_candidate_from_conversion quá lớn,
    # nhưng với p 512-bit và q ~570-bit, n ~1082-bit, Python xử lý được.
    n_candidate = mid_p * q_candidate_from_conversion

    if n_candidate == n_val:
        # Tìm thấy một ứng cử viên khớp n_val
        # Kiểm tra xem nó có phải là số nguyên tố và q cũng vậy không
        if isPrime(mid_p):
            q_check = n_val // mid_p
            if mid_p * q_check == n_val and q_check == q_candidate_from_conversion and isPrime(q_check):
                p_solution = mid_p
                q_solution = q_check
                print(f"Tìm thấy p, q khớp tại mid_p = {mid_p}")
                break # Thoát vòng lặp tìm kiếm
        # Nếu mid_p không nguyên tố, hoặc q không nguyên tố, có thể giải pháp này chưa đúng
        # Hoặc p đúng nhưng q_candidate_from_conversion không phải là q thực sự của n
        # Trong trường hợp này, p thực sự có thể rất gần mid_p.
        # Ta có thể thử điều chỉnh high_p = mid_p để tìm kiếm tiếp ở vùng lân cận
        # Tuy nhiên, với cách này, thường khi n_candidate == n_val thì mid_p chính là p.
        # Nếu không phải, có thể thử low = mid + 1 để xem có p lớn hơn một chút không
        # Hoặc high = mid - 1 để xem có p nhỏ hơn không.
        # Vì hàm f(p) = p * int(str(p),13) tăng đơn điệu, nghiệm là duy nhất.
        # Nên nếu n_candidate == n_val, thì mid_p phải là p.
        # Việc kiểm tra isPrime ở đây là để xác nhận.
        
        # Nếu mid_p không phải nguyên tố, ta cần tìm p nguyên tố gần đó.
        # Tuy nhiên, vòng lặp while True trong code gốc đảm bảo p là nguyên tố.
        # Nên mid_p tìm được ở đây PHẢI là p.
        p_solution = mid_p # Chấp nhận giải pháp này
        q_solution = n_val // p_solution
        break


    if n_candidate < n_val:
        low_p = mid_p + 1
    else: # n_candidate > n_val
        high_p = mid_p - 1

# Sau vòng lặp, nếu p_solution chưa được tìm thấy nhưng low_p và high_p đã hội tụ
# p_solution có thể là low_p hoặc high_p (hoặc giá trị gần đó)
if p_solution == -1:
    print("Không tìm thấy p_solution khớp n_val chính xác trong vòng lặp chính.")
    # Kiểm tra các giá trị lân cận của điểm hội tụ
    # low_p là giá trị nhỏ nhất sao cho low_p * int(str(low_p),13) >= n_val (nếu hội tụ đúng)
    # high_p là giá trị lớn nhất sao cho high_p * int(str(high_p),13) <= n_val
    # P thật sự có thể là một trong hai hoặc một giá trị ở giữa nếu chúng rất gần nhau.
    
    # Thử kiểm tra low_p (vì nó là p nhỏ nhất làm n_candidate >= n_val)
    print(f"Kiểm tra giá trị hội tụ low_p = {low_p}")
    p_try = low_p
    q_try_conv = int(str(p_try), 13)
    if p_try * q_try_conv == n_val and isPrime(p_try):
        q_try_div = n_val // p_try
        if q_try_div == q_try_conv and isPrime(q_try_div):
            p_solution = p_try
            q_solution = q_try_div
            print(f"Tìm thấy p, q tại low_p = {p_try}")

    if p_solution == -1: # Nếu low_p không hoạt động, thử high_p (hoặc low_p - 1)
         print(f"Kiểm tra giá trị hội tụ high_p = {high_p} (hoặc low_p-1)")
         p_try = high_p # Hoặc p_try = low_p -1
         if p_try > 0:
            q_try_conv = int(str(p_try), 13)
            if p_try * q_try_conv == n_val and isPrime(p_try):
                q_try_div = n_val // p_try
                if q_try_div == q_try_conv and isPrime(q_try_div):
                    p_solution = p_try
                    q_solution = q_try_div
                    print(f"Tìm thấy p, q tại high_p = {p_try}")


if p_solution != -1 and q_solution != -1:
    print(f"\nTìm thấy p = {p_solution}")
    print(f"Tìm thấy q = {q_solution}")

    # Xác minh lại
    if not isPrime(p_solution):
        print("LỖI: p_solution không phải số nguyên tố!")
        exit()
    if not isPrime(q_solution):
        print("LỖI: q_solution không phải số nguyên tố!")
        exit()
    if int(str(p_solution), 13) != q_solution:
        print("LỖI: q_solution không khớp với int(str(p_solution), 13)!")
        exit()
    if p_solution * q_solution != n_val:
        print("LỖI: p_solution * q_solution != n_val!")
        exit()
    
    print("\nXác minh p và q thành công.")

    # Bước 5: Giải mã RSA
    phi = (p_solution - 1) * (q_solution - 1)
    
    try:
        d_val = pow(e_val, -1, phi)
        print(f"d = {d_val}")
    except ValueError:
        print(f"Lỗi: e_val={e_val} không có nghịch đảo modular với phi={phi}. GCD(e,phi) != 1.")
        exit()

    m_val = pow(ct_val, d_val, n_val)
    
    try:
        flag_bytes = long_to_bytes(m_val)
        print(f"FLAG: {flag_bytes.decode('utf-8', errors='replace')}")
    except Exception as e:
        print(f"Lỗi khi chuyển đổi message sang bytes hoặc decode: {e}")
        print(f"Message (long): {m_val}")

else:
    print("\nKhông tìm thấy p và q hợp lệ.")
    print(f"Giá trị cuối cùng của low_p: {low_p}")
    print(f"Giá trị cuối cùng của high_p: {high_p}")