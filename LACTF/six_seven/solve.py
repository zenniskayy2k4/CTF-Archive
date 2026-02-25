from Crypto.Util.number import long_to_bytes

n=44451118578534524554238951673704442196011386197418311191598286700074149280747534500612578381265456040200946789366814928240182973725486414585233865631831582699615146796098939172006490351620734403652486968034497396992208060279887727121880117638418909718789423666625159074604316653344842138720447706303813689873824572584148645634178338277759584236708895272660201669352050715659866435742801991218489456458567437047445950451471102669689679833201737122769917713658428925583609714326000319401233735428512572522774369559
c=30014414502640601782774070768930211571870884809775568211715819820831811392891258270007592624119179868601113211421579291759187777316063309367453163353615400633386883610569094028993661465514002779006716607858288733701171151222826063059839657049656559377347155472788996524288729877235074649061055719418300500177619229641740860159470439410586272844176416982410382699333097122535072378408255757826248513291430057253155771192081034782057152244423907324476838657687225667974192338708925085276611786097953996268807072006
e = 65537

def solve_backtracking():
    # p và q đều có 256 chữ số, kết thúc bằng 7
    # n có tối đa 512 chữ số
    n_str = str(n)[::-1] # Đảo ngược để xử lý hàng đơn vị trước
    
    # Duyệt DFS: (vị trí chữ số hiện tại, giá trị p tạm thời, giá trị q tạm thời)
    def dfs(idx, p_val, q_val):
        # Nếu đã duyệt hết 256 chữ số của p và q
        if idx == 256:
            if p_val * q_val == n:
                return p_val, q_val
            return None

        # Thử các kết hợp chữ số 6 hoặc 7 cho p_idx và q_idx
        # Riêng chữ số đầu tiên (idx=0) phải là 7
        options = [7] if idx == 0 else [6, 7]
        
        for pi in options:
            for qi in options:
                new_p = p_val + pi * (10**idx)
                new_q = q_val + qi * (10**idx)
                
                # Kiểm tra xem chữ số thứ idx của (new_p * new_q) có khớp với n không
                if str(new_p * new_q).zfill(idx+1)[-(idx+1)] == n_str[idx]:
                    res = dfs(idx + 1, new_p, new_q)
                    if res: return res
        return None

    return dfs(0, 0, 0)

print("[*] Đang tìm p, q bằng Backtracking...")
result = solve_backtracking()

if result:
    p, q = result
    print(f"[+] Tìm thấy p: {p}")
    print(f"[+] Tìm thấy q: {q}")
    
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    m = pow(c, d, n)
    print(f"\n[!] FLAG: {long_to_bytes(m).decode()}")
else:
    print("[-] Không tìm thấy kết quả.")