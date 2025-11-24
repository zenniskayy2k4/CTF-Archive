import gmpy2

p = 42823
q = 6409

# Sử dụng hàm có sẵn từ thư viện gmpy2
# gcdext(a, b) trả về (g, u, v) sao cho a*u + b*v = g
g, u, v = gmpy2.gcdext(p, q)

print("Solution from gmpy2:")
print(f"GCD: {g}")
print(f"u: {u}")
print(f"v: {v}")
print(f"Bigger number: {max(u, v)}")

# Kiểm tra lại phương trình
if p * u + q * v == g:
    print("\nVerification successful.")
else:
    print("\nVerification failed.")