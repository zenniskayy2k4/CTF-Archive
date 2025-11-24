e = 65537
n1 = 129092526753383933030272290277107300767707654330551632967994396398045326531320303963182497488182474202461120692162734880438261410066549845639992024037416720228421076282632904598519793243067220342037144864237020757818263128301138206081187472003821789897063195512919097350247829148288118913456964033001399074373
n2 = 108355113470836594630192960651980673780103497896732213011958303033575870030505528169174729530490405910634291415346360688290452976527316909469646908289732023715737439312572012648165819533234604850608390233938174081867146846639110685928136323983961395098632140681799175543046722931901766226759894951292033805879
d1 = 88843495989869871001559754882918076779858404440780391818567639602073173623287821751315349650577023725245222074965050035045516207303078461168168819365025746973589245131570143944718203046457391270418459087764266630890566079039821735168805805866019315142070438225092171304343352469029480503113942986147848666077
d2 = 94565144275929764017241865812435668644218918537941567711225644474418458115544003036362558987818610553975855551983688286593672386482543188020042082319191545660551324293738920214028045344249670512999137548994496577128446165632885775744795722253354007167294035878656056258332703809173397147948143695113558988035


def factor_from_edn_sagemath(e, d, n):
    """
    Phân tích n bằng SageMath.
    Cú pháp gần như y hệt Python, nhưng các hàm pow, gcd
    được Sage tự động tối ưu hóa ở tầng C/Assembly.
    """
    # Trong Sage, mọi số nguyên đều là kiểu dữ liệu có độ chính xác tùy ý.
    # Không cần import hay chuyển đổi gì cả.
    m = e * d - 1
    
    # Sage có hàm tích hợp để làm việc này: valuation(m, 2)
    s = m.valuation(2) 
    t = m // (2^s)
    
    # Thử với các "nhân chứng" a
    # Sage có các hàm như next_prime() rất tiện lợi
    a = 2 
    while True:
        # power_mod() là hàm lũy thừa module của Sage, cực nhanh
        x = power_mod(a, t, n)
        
        if x != 1 and x != n - 1:
            for _ in range(s):
                y = power_mod(x, 2, n)
                if y == 1:
                    # gcd() của Sage cũng được tối ưu
                    p = gcd(x - 1, n)
                    q = n // p
                    return p, q
                if y == n - 1:
                    break # Thử a khác
                x = y
            else: # Nếu vòng lặp trên không bị break
                y = power_mod(x, 2, n)
                if y == 1:
                    p = gcd(x - 1, n)
                    q = n // p
                    return p, q

        # Nếu a hiện tại không thành công, thử số nguyên tố tiếp theo
        a = next_prime(a)


print("[+] Bắt đầu phân tích n1 (SageMath)...")
p1, q1 = factor_from_edn_sagemath(e, d1, n1)
print(f"    n1 = {n1}")
print(f"    p1 = {p1}")
print(f"    q1 = {q1}")
if p1 * q1 == n1:
    print("    Kiểm tra n1: OK\n")
else:
    print("    Kiểm tra n1: THẤT BẠI\n")


print("[+] Bắt đầu phân tích n2 (SageMath)...")
p2, q2 = factor_from_edn_sagemath(e, d2, n2)
print(f"    n2 = {n2}")
print(f"    p2 = {p2}")
print(f"    q2 = {q2}")
if p2 * q2 == n2:
    print("    Kiểm tra n2: OK")
else:
    print("    Kiểm tra n2: THẤT BẠI")