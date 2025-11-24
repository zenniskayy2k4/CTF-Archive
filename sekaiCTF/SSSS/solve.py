from pwn import *
import numpy as np

# ... (Hàm power, inv, solve_linear_system giữ nguyên) ...
p = 2**256 - 189
def power(a,b): return pow(a,b,p)
def inv(a): return pow(a,-1,p)
def solve_linear_system(A, b):
    num_vars=A.shape[1];aug=np.hstack([A,b.reshape(-1,1)]).astype(object);pivot_row=0;pivot_cols=[]
    for col in range(num_vars):
        if pivot_row<aug.shape[0]:
            pivot=pivot_row
            while pivot<aug.shape[0] and aug[pivot,col]==0:pivot+=1
            if pivot<aug.shape[0]:
                aug[[pivot_row,pivot]]=aug[[pivot,pivot_row]];pivot_cols.append(col);inv_val=inv(aug[pivot_row,col]);aug[pivot_row,:]=(aug[pivot_row,:]*inv_val)%p
                for i in range(aug.shape[0]):
                    if i!=pivot_row:factor=aug[i,col];aug[i,:]=(aug[i,:]-factor*aug[pivot_row,:])%p
                pivot_row+=1
    particular_sol=np.zeros(num_vars,dtype=object)
    for i in range(len(pivot_cols)-1,-1,-1):
        pivot_col=pivot_cols[i];particular_sol[pivot_col]=aug[i,-1]
        for j in range(pivot_col+1,num_vars):particular_sol[pivot_col]=(particular_sol[pivot_col]-aug[i,j]*particular_sol[j])%p
    free_cols=[i for i in range(num_vars) if i not in pivot_cols]
    if not free_cols:return particular_sol,None
    homogeneous_sol=np.zeros(num_vars,dtype=object);free_col=free_cols[0];homogeneous_sol[free_col]=1
    for i in range(len(pivot_cols)-1,-1,-1):
        pivot_col=pivot_cols[i]
        for j in range(pivot_col+1,num_vars):homogeneous_sol[pivot_col]=(homogeneous_sol[pivot_col]-aug[i,j]*homogeneous_sol[j])%p
    return particular_sol,homogeneous_sol

def get_poly_data(r, t):
    log.info(f"Interacting with server for t={t}...")
    r.sendline(str(t).encode())
    
    xs = [i for i in range(1, t + 1)]
    ys = []
    
    for x in xs:
        r.sendline(str(x).encode())
        y = int(r.recvline().strip())
        ys.append(y)
    
    log.info("Data collected. Now performing calculations...")
    
    A = np.zeros((t, t + 1), dtype=object)
    for i in range(t):
        x = xs[i]
        for j in range(t + 1):
            A[i, j] = power(x, j)
            
    b = np.array(ys, dtype=object)
    solution = solve_linear_system(A, b)
    # Trả về cả các điểm đã truy vấn để xác minh
    return solution, xs, ys

def poly_eval(f_coeffs, x):
	return sum(c * power(x, i) for i, c in enumerate(f_coeffs)) % p

# --- Main exploit ---

conn = remote("ssss.chals.sekai.team", 1337, ssl=True)

# --- Round 1 ---
t1 = 20
(C1p, C1h), xs1, ys1 = get_poly_data(conn, t1)
conn.sendline(b"0")
conn.recvline()

# --- Round 2 ---
t2 = 21
(C2p, C2h), _, _ = get_poly_data(conn, t2)

# --- Collect all possible candidates ---
log.info("Collecting all plausible secret candidates...")
all_candidates = set()
for i in range(t1 + 1):
    for j in range(t2 + 1):
        if C1h[i] == 0: continue
        
        mu = 1
        rhs = (C2p[j] - C1p[i] + mu * C2h[j]) % p
        lam = (rhs * inv(C1h[i])) % p
        
        C1_candidate = (C1p + lam * C1h) % p
        C2_candidate = (C2p + mu * C2h) % p
        
        intersection = set(C1_candidate) & set(C2_candidate)
        
        # Lấy tất cả các ứng cử viên từ các giao điểm có kích thước nhỏ
        if 0 < len(intersection) <= 2:
            all_candidates.update(intersection)

log.info(f"Found {len(all_candidates)} candidates to verify.")

# --- Verify candidates ---
final_secret = -1
for s in all_candidates:
    # Giả sử s là secret. Nó có thể ở bất kỳ vị trí k nào trong C1
    for k in range(t1 + 1):
        if C1h[k] == 0: continue
        
        # Giả sử C1[k] = s. Giải lam
        # s = C1p[k] + lam * C1h[k]
        try:
            lam = ((s - C1p[k]) * inv(C1h[k])) % p
        except ZeroDivisionError:
            continue
            
        # Tái tạo lại C1
        C1_reconstructed = (C1p + lam * C1h) % p
        
        # Xác minh với điểm dữ liệu đầu tiên (x=1, y=ys1[0])
        x_verify = xs1[0]
        y_verify = ys1[0]
        
        if poly_eval(C1_reconstructed, x_verify) == y_verify:
            log.success(f"Verification successful! Secret is {s}")
            final_secret = s
            break
    if final_secret != -1:
        break

if final_secret == -1:
    log.error("Could not find the correct secret after verification.")
    exit(1)

# Gửi đáp án và nhận flag
conn.sendline(str(final_secret).encode())
flag = conn.recvall()
log.success(f"Flag: {flag.decode()}")