from collections import Counter
from Crypto.Util.number import long_to_bytes, bytes_to_long

with open("output.txt","r") as f:
    lines = [ln.strip() for ln in f if ln.strip()]

# tách các dòng 0/1 và dòng hex cuối
bins_by_len = {}
hex_tail = None
for ln in lines:
    if all(c in "01" for c in ln):
        bins_by_len.setdefault(len(ln), []).append(ln)
    else:
        hex_tail = ln

# chọn nhóm có nhiều dòng nhất (độ dài đúng)
bitlen, rows = max(bins_by_len.items(), key=lambda kv: len(kv[1]))
n = len(rows)

# đa số theo cột: nhiều '1' -> keybit=0 ; ít '1' -> keybit=1
cols = list(zip(*rows))
ones = [col.count('1') for col in cols]
key_bits = ['0' if c > n/2 else '1' for c in ones]

# chuẩn hóa thành bitstring
bits = ''.join(key_bits)
bits = bits.zfill(((len(bits)+7)//8)*8)  # pad để đủ bội số của 8

# chuyển thành bytes
key_bytes = bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))

print("[*] repr(key_bytes):", repr(key_bytes))

# decode UTF-8 với fallback
try:
    key_str = key_bytes.decode('utf-8')
except:
    key_str = key_bytes.decode('utf-8', 'replace')

print("[*] decoded (with replacement):", key_str)

# Áp dụng các thay thế trong đề
flag = key_str.replace("!", "1").replace("[", "_")
if flag.count("f") >= 2:
    i = flag.find("f")
    flag = flag[:i] + "F" + flag[i+1:]

print("\n[FLAG]", flag)