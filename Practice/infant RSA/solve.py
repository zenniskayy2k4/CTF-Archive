import math
from Crypto.Util.number import long_to_bytes

# Các giá trị đã cho từ file infant_rsa.py
n = 144984891276196734965453594256209014778963203195049670355310962211566848427398797530783430323749867255090629853380209396636638745366963860490911853783867871911069083374020499249275237733775351499948258100804272648855792462742236340233585752087494417128391287812954224836118997290379527266500377253541233541409
c = 120266872496180344790010286239079096230140095285248849852750641721628852518691698502144313546787272303406150072162647947041382841125823152331376276591975923978272581846998438986804573581487790011219372437422499974314459242841101560412534631063203123729213333507900106440128936135803619578547409588712629485231
hint = 867001369103284883200353678854849752814597815663813166812753132472401652940053476516493313874282097709359168310718974981469532463276979975446490353988
e = 65537

# --- BƯỚC 2: Dùng `hint` để tìm các bit cuối của s = p+q ---

# Ta có `hint` là 500 bit cuối của `phi`.
# Điều này có nghĩa là: phi ≡ hint (mod 2^500)
# Modulo M chính là 2^500
M = 1 << 500

# Ta biết: phi = n - (p+q) + 1. Đặt s = p+q.
# => n - s + 1 ≡ hint (mod M)
# Chuyển vế để tìm s:
# s ≡ n + 1 - hint (mod M)
s_lower_bits = (n + 1 - hint) % M

print(f"[+] Đã tìm thấy 500 bit cuối của s = p+q: {s_lower_bits}")

# --- BƯỚC 3: Brute-force các bit đầu của s ---

# p và q là số 512-bit, nên tổng s = p+q sẽ là số 513-bit.
# Ta đã biết 500 bit cuối, vậy chỉ còn thiếu khoảng 13 bit đầu.
# Ta có thể biểu diễn s = s_lower_bits + k * M, với k là một số nguyên nhỏ.
# Ta sẽ thử các giá trị của k.
for k in range(1, 2**14): # Thử duyệt qua các giá trị có thể của các bit đầu
    s_candidate = s_lower_bits + k * M

    # Kiểm tra xem s_candidate có hợp lệ không.
    # Nếu s = p+q và n = p*q, thì p và q là nghiệm của x² - s*x + n = 0.
    # Để có nghiệm nguyên, delta = s² - 4n phải là số chính phương.
    delta = s_candidate**2 - 4*n
    if delta >= 0:
        # Kiểm tra xem delta có phải là số chính phương không
        sqrt_delta = math.isqrt(delta)
        if sqrt_delta**2 == delta:
            print(f"[+] Tìm thấy s chính xác sau khi thử k = {k}")
            s = s_candidate
            
            # --- BƯỚC 4 & 5: Khôi phục p, q và giải mã ---
            p = (s + sqrt_delta) // 2
            q = (s - sqrt_delta) // 2

            assert p * q == n, "Khôi phục p và q không chính xác!"
            print(f"[+] Khôi phục thành công p và q!")
            phi = (p-1) * (q-1)
            d = pow(e, -1, phi)
            m = pow(c, d, n)
            flag = long_to_bytes(m)
            print(f"\n[*] Flag: {flag.decode()}")
            break
