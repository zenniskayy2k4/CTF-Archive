
import json
import numpy as np

q = 3329
n = 512
k = 4

# Re-load data inside Sage
with open("keys.json", "r") as f:
    keys = json.load(f)

A1 = np.array(keys["A_1"])
A2 = np.array(keys["A_2"])
u1 = np.array(keys["u_1"])
u2 = np.array(keys["u_2"])
t1 = np.array(keys["t_1"])
v1 = np.array(keys["v_1"])

# Difference
D_T = (A1.T - A2.T) % q
du = (u1 - u2) % q

# Target vector flattened
Y = vector(GF(q), du.flatten())

# Build the Matrix
# We need to represent the operation: sum(convolve(a, b))
# a is length 4. b is length 512.
# The convolution is mod x^512 + 1.
# This corresponds to a negacyclic matrix, but since 'a' is very short, 
# it's a very sparse banded matrix.

rows_list = []

for i in range(k): # For each output equation (0..3)
    # The i-th 'row' from the loop 'for row in A.T'
    # In the python code: row = A.T[i] (Shape 4x4)
    # It zips with r (Shape 4x512)
    
    block_rows = []
    
    # We construct the 512 rows corresponding to this equation i
    # We need to sum up contributions from r[0]...r[3]
    
    # To do this efficiently in Sage, we iterate 0..511 (rows of the block)
    for row_idx in range(n):
        full_row = []
        for j in range(k): # For each r[j]
            # Get the coefficient vector 'a' = D_T[i][j] (length 4)
            a = D_T[i][j]
            
            # Construct row of convolution matrix for 'a'
            # Matrix column c corresponds to r[j][c]
            # M[r, c] = coefficient of x^r in (a(x) * x^c)
            # a(x) = a0 + a1 x + a2 x^2 + a3 x^3
            # x^c * a(x) = a0 x^c + ... + a3 x^{c+3}
            # We want the coefficient at position row_idx.
            
            # This is equivalent to: M[r, c] = a[r - c] (with negacyclic wrap)
            
            vec = [0] * n
            for coef_idx, coef_val in enumerate(a):
                target_pos = (row_idx - coef_idx)
                sign = 1
                if target_pos < 0:
                    target_pos += n
                    sign = -1 # Negacyclic property x^n = -1
                
                # However, the python code uses np.convolve(a, b).
                # 'a' is kernel. 'b' is input.
                # numpy convolve result index k is sum(a[m]*b[k-m])
                # res[k] = sum(a[m] * b[k-m])
                # We need the coefficient for r[j][col].
                # r[j] is 'b'. 'col' is index in 'b'. 'm' is index in 'a'.
                # output index 'row_idx' = col + m
                # => col = row_idx - m
                
                if row_idx == (target_pos + coef_idx) % n: # verification logic
                     pass
                
                # We place coef_val at column (row_idx - coef_idx) with sign
                
                col_idx = row_idx - coef_idx
                val = coef_val
                if col_idx < 0:
                    col_idx += n
                    val = -val
                
                vec[col_idx] = (vec[col_idx] + val) % q
            
            full_row.extend(vec)
        rows_list.append(full_row)

M = Matrix(GF(q), rows_list)

print("Solving linear system...")
# Solve M * r_flat = Y
r_flat = M.solve_right(Y)

# Reshape r
r = np.array(r_flat).reshape((k, n)).astype(int)

# Decrypt
# v1 = t1 * r + e2 + m
# m ~ v1 - t1 * r

def vec_poly_mul(v0, v1):
    def poly_mul(a, b):
        res = np.convolve(a, b)
        for i in range(n, len(res)):
            res[i - n] = (res[i - n] - res[i]) % q 
        return res[:n]
    
    total = np.zeros(n, dtype=int)
    for a, b in zip(v0, v1):
        total = (total + poly_mul(a, b)) % q
    return total

tr = vec_poly_mul(t1, r)
diff = (v1 - tr) % q

# Decode bits
# 0 maps to ~0
# 1 maps to ~ (q+1)//2 = 1665
limit_low = 1665 // 2
limit_high = (1665 + 3329) // 2

bits = []
for val in diff:
    if limit_low < val < limit_high:
        bits.append(1)
    else:
        bits.append(0)

# Bits to chars
chars = []
for i in range(0, len(bits), 8):
    byte = bits[i:i+8]
    val = int("".join(map(str, byte)), 2)
    chars.append(chr(val))

print("Flag:", "".join(chars))
    