import re

# --- đọc dữ liệu từ output.txt ---
txt = open("output.txt","r").read()
vals = dict((k, Integer(v)) for k, v in re.findall(r'([a-zA-Z0-9_]+)\s*=\s*([0-9]+)', txt))
N  = Integer(vals["N"])
e  = Integer(vals["e"])
c  = Integer(vals["c"])
# e1,e2 có cũng không cần
print("[+] Loaded N bits =", N.nbits())

# --- factor N ---
print("[*] Factoring N ...")
fac = factor(N)          # Sage dùng ECM/MPQS nội bộ
print("[+] factor(N) =", fac)

# Kỳ vọng fac có dạng p^r * q
primes = []
for P, k in fac:        # P prime, k exponent
    primes.append((Integer(P), int(k)))
# tách p^r và q
primes.sort(key=lambda t: -t[1])   # thừa số có mũ lớn nhất là p^r
(p, r) = primes[0]
# q là thừa số còn lại (mũ 1)
q = [P for P,k in primes if P != p][0]

print(f"[+] p bits={p.nbits()}, r={r}, q bits={q.nbits()}")

# --- tính phi(N) ---
phi = p**(r-1) * (p-1) * (q-1)
print("[+] phi bits =", phi.nbits())

# --- private exponent & giải mã ---
d = inverse_mod(e, phi)
m = pow(c, d, N)

# --- chuyển về bytes/flag ---
def long_to_bytes(n):
    # giữ nguyên độ dài hợp lý (tự cắt bỏ leading 00)
    blen = (n.nbits() + 7)//8
    return Integer(n).to_bytes(blen, 'big').lstrip(b'\x00')

pt = long_to_bytes(m)
print("[+] Plaintext (bytes):", pt)
try:
    print("[+] Ascii:", pt.decode())
except:
    print("[+] (not pure ascii)")
