# 1. Khởi tạo các tham số từ file chal
p = 0xbde3c425157a83cbe69cee172d27e2ef9c1bd754ff052d4e7e6a26074efcea673eab9438dc45e0786c4ea54a89f9079ddb21
a = 5
b = 7
target_x = 0x686be42f9c3f431296a928c288145a847364bb259c9f5738270d48a7fba035377cc23b27f69d6ae0fad76d745fab25d504d5

# Tạo trường hữu hạn và đường cong elliptic
F = GF(p)
E = EllipticCurve(F, [a, b])
print(f"[*] Elliptic Curve: {E}")

# 2. Tính toán scalar k
N = E.order()
print(f"[*] Curve order N: {N}")
factors = N.factor()
print(f"[*] Factors of N: {factors}")
# Lấy thừa số nguyên tố thứ 4 (chỉ số 3)
k = factors[3][0]
print(f"[*] Scalar k: {k}")

# 3. Tìm điểm Q từ target_x
# y^2 = x^3 + a*x + b
y_squared = target_x^3 + a*target_x + b
# Tìm căn bậc hai trong trường GF(p)
# Có hai nghiệm y và -y (hoặc p-y)
target_y_solutions = F(y_squared).sqrt(all=True)
print(f"[*] Found {len(target_y_solutions)} possible y-coordinates for Q")

if not target_y_solutions:
    print("[!] No point Q found on the curve with the given x-coordinate.")
else:
    # Lặp qua các điểm Q khả dĩ (thường là 2)
    for target_y in target_y_solutions:
        Q = E(target_x, target_y)
        print(f"\n[*] Testing with point Q = {Q}")
        
        # 4. Thực hiện "chia vô hướng" để tìm các điểm P
        # P_candidates = Q.division_points(k)
        # Note: division_points có thể chậm, cách khác hiệu quả hơn là dùng isogeny
        # Tuy nhiên, với k nhỏ, nó vẫn chạy tốt
        try:
            P_candidates = Q.division_points(k)
            print(f"[*] Found {len(P_candidates)} candidate points for P")
    
            # 5. Trích xuất flag từ các điểm P
            for P in P_candidates:
                # Lấy tọa độ x
                x_p = P.x()
                
                # Chuyển số nguyên lớn sang bytes
                m = int(x_p)
                # +7 // 8 là cách làm tròn lên để lấy đủ số byte
                m_bytes = m.to_bytes((m.bit_length() + 7) // 8, 'big')
                
                # Thử decode và in ra flag
                try:
                    flag_content = m_bytes.decode('utf-8')
                    # Kiểm tra xem có phải là ký tự in được không
                    if all(c.isprintable() for c in flag_content):
                        print(f"\n[+] Possible Flag Found!")
                        print(f"    Flag content: {flag_content}")
                        print(f"    Full flag: ictf{{{flag_content}}}")
                except UnicodeDecodeError:
                    # Bỏ qua nếu không phải là chuỗi utf-8 hợp lệ
                    pass
        except Exception as e:
            print(f"[!] An error occurred during division_points for Q={Q}: {e}")