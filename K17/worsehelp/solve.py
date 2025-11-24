# sage
# -*- coding: utf-8 -*-

from Crypto.Util.number import long_to_bytes
import re
import socket
from sage.all import Integer, Zmod, PolynomialRing, power_mod, is_prime
from sage.crypto.coppersmith import small_roots

def boneh_durfee_attack(c_py, e_py, n_py):
    print("\n[+] Bắt đầu tấn công Boneh-Durfee...")

    c = Integer(c_py)
    e = Integer(e_py)
    n = Integer(n_py)

    # Định nghĩa vành đa thức và các biến một cách tương thích với Python
    P = PolynomialRing(Zmod(e), names=['x', 'y'])
    (x, y) = P.gens()
    
    # Định nghĩa đa thức P(x,y) = x*(n-y) + 1
    pol = x * (n - y) + 1

    # Đặt giới hạn trên cho các nghiệm
    # k ~ 512 bits, s = p+q-1 ~ 1025 bits
    X = 2^513
    Y = 2^1026

    print("[+] Đang tìm các nghiệm nhỏ của đa thức (có thể mất vài phút)...")
    
    # === SỬA LỖI ATTRIBUTEERROR TẠI ĐÂY ===
    # Gọi small_roots như một hàm độc lập, không phải là một phương thức
    # Dòng cũ: roots = pol.small_roots(X=X, Y=Y, m=2, t=4)
    roots = small_roots(pol, (X, Y), m=2, t=4)
    # =====================================

    if not roots:
        print("[-] Tấn công Boneh-Durfee thất bại. Không tìm thấy nghiệm nào.")
        return

    print(f"[+] Tìm thấy {len(roots)} nghiệm khả thi. Đang kiểm tra...")
    for root in roots:
        k_sol, s_sol = root
        k = Integer(k_sol)
        s = Integer(s_sol)
        
        phi_candidate = n - s
        
        if phi_candidate <= 0 or (1 + k * phi_candidate) % e != 0:
            continue
            
        d_candidate = (1 + k * phi_candidate) // e
        
        try:
            m = power_mod(c, d_candidate, n)
            flag_bytes = long_to_bytes(int(m))
            # SECSO là một phần của tên miền, khả năng cao có trong flag
            if b'SECSO' in flag_bytes or b'flag' in flag_bytes:
                print(f"\n[+] TẤN CÔNG THÀNH CÔNG!")
                print(f"    - Tìm thấy k = {k}")
                print(f"    - Tìm thấy s = {s}")
                print(f"    - Khóa bí mật d = {d_candidate}")
                print("\n[+] FLAG:")
                print(flag_bytes.rstrip(b'\x00').decode())
                return
        except Exception:
            continue
            
    print("\n[-] Đã thử tất cả các nghiệm nhưng không tìm thấy flag.")

def main():
    # a, b = find_parameters()
    # c, e, n = get_challenge_params(a, b)
    
    # Dán các giá trị đã biết từ lần chạy trước để tiết kiệm thời gian
    c = 1356778572733072598899117810387249992574522959164660158978261227599306176195384005969103511885035609949864172916964471191743757298897353816579670563539875819406755622758747955982682367539947525616869384734991449523877021132573181857999476082561104420234106903004966701754408244596159613231661548456086163263848433784964901263660769495022790237388501738303494952427153400024710233813497481386982324358968302813838873795431503674379336123877734986831464076597403964553322683446687149717152655797447364938904177713967356511806145361371106284104812683802090280022366316857295933966015935354011435976628458981967283127983
    e = 9235259145423256892122147278594405629385984689635295048952338767588488293611241423612199983175016428878909516499589565756753383793998080125165071232140317910880708917414368477930319585713224345586241703538960089588377048023270838450395698917623646654837556124054011784700397196315415041979923778359687545152111655059718006961990186440609454588036329862232531990445883821442518635909212877134474497367702431138917507977283128545885053360665857628397214947463838495849081554623821639921833412395428405488575665432752447137325585168763830506567729788349487049486040780771779645494959821109054275642976547125233126064705
    n = 26655408169980069210647581523602779478383892791339633948356189966966764750165134594036664344616717049933468489628650785388326960151667345490717171048101455362566962665238961659030316534689141077384698564134139632695609188803626466763599399566394268096308569815703206388042056345258250386433839660150434400832811052444460080481324647584218234188638113017330573479354360529764080129533591285518499302216709805065611198775844489705004103428358877462001690093040584862237132523022766091068430370508379474771150405568772531525628897113571198108361167861758593933680578287574630561945653761414928747417980154682790756164343

    if c and e and n:
        boneh_durfee_attack(c, e, n)

if __name__ == "__main__":
    main()