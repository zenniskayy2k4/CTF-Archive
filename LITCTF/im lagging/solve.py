# pip install pwntools
# Python 3.9+
import re
from pwn import remote, context

HOST, PORT = "litctf.org", 31784
M  = (1 << 59) - 1                      # 2^59 - 1
P1 = 179951
P2 = 3203431780337
LAGS_TOTAL = 50

context.log_level = "error"

def crt_merge(a1, m1, a2, m2):
    # x ≡ a1 (mod m1), x ≡ a2 (mod m2)  with gcd(m1, m2)=1
    inv = pow(m1, -1, m2)
    t = ((a2 - a1) % m2) * inv % m2
    return (a1 + m1 * t) % (m1 * m2)

def read_outputs(expect_n=10000):
    """Connect, press Enter, parse đúng 10000 số."""
    io = remote(HOST, PORT, ssl=False)
    io.recvuntil(b"Press enter")
    io.sendline()
    buf = b""
    nums = []
    while len(nums) < expect_n:
        chunk = io.recv(timeout=2)
        if not chunk:
            break
        buf += chunk
        nums = list(map(int, re.findall(rb"\d+", buf)))
    if len(nums) != expect_n:
        raise RuntimeError(f"expected {expect_n} numbers, got {len(nums)}")
    return io, [n % M for n in nums]

def gather_candidate_as(y, max_i=800):
    """Sinh các ứng viên 'a' bằng CRT từ nhiều bộ ba liên tiếp."""
    cands = set()
    up = min(max_i, len(y) - 2)
    for i in range(up):
        d = (y[i+1] - y[i]) % M
        if d == 0:
            continue
        parts = []
        ok = True
        for p in (P1, P2):
            if d % p == 0:
                ok = False
                break
            ap = ((y[i+2] - y[i+1]) % p) * pow(d % p, -1, p) % p
            parts.append(ap)
        if not ok:
            continue
        a = crt_merge(parts[0], P1, parts[1], P2)
        cands.add(a)
    return list(cands)

def score_candidate(y, a, max_bad_lags=60):
    """Tính điểm ứng viên: số bước khớp khi phát hiện lag dần dần."""
    inv50 = pow(50, -1, M)
    # ở prefix (chưa lộ lag), r1 = a*r0 + 50*c => c từ 2 giá trị đầu
    c = ((y[1] - a * y[0]) % M) * inv50 % M

    known = set()
    remain = LAGS_TOTAL
    matches = 0

    r_prev = y[0]  # chưa có lag nào trừ đi
    for t in range(1, len(y)):
        # r_curr = y[t] - sum_{d in known, t-d>=0} y[t-d]
        r_curr = y[t]
        if known:
            for d in known:
                if t - d >= 0:
                    r_curr = (r_curr - y[t - d]) % M

        pred = (a * r_prev + c * remain) % M
        if r_curr == pred:
            matches += 1
            r_prev = r_curr
        else:
            # Một lag vừa “thoát seed” tại t -> d_new = t
            known.add(t)
            remain -= 1
            # cùng khung t, sau khi biết d_new, r'_t = r_curr - y[t - d_new] = r_curr - y[0]
            r_prev = (r_curr - y[0]) % M
            # Ứng viên sai sẽ đếm lag rất nhiều -> cắt sớm
            if len(known) > max_bad_lags:
                break

    # Dự đoán y_next theo các lag đã biết
    N = len(y)
    y_next = 0
    for d in known:
        y_next = (y_next + y[N - d]) % M
    missing = LAGS_TOTAL - len(known)
    if missing == 1:
        y_next = (y_next + y[0]) % M
    # Trả (điểm, dự đoán, số lag đã phát hiện)
    # Điểm: số match - phạt nếu “phát hiện” > 50
    score = matches - max(0, len(known) - LAGS_TOTAL) * 100
    return score, y_next, len(known)

def solve_next(y):
    # 1) lấy tập ứng viên a
    cands = gather_candidate_as(y, max_i=800)
    if not cands:
        raise RuntimeError("Không tạo được ứng viên 'a' nào (hiếm).")

    # 2) chấm điểm từng ứng viên, lấy cái tốt nhất
    best = None
    for a in cands:
        score, guess, k = score_candidate(y, a)
        if best is None or score > best[0]:
            best = (score, guess, a, k)

    # 3) kết quả tốt nhất
    score, y_next, a_best, found = best
    # (tuỳ thích) assert found in [49, 50] để tự tin hơn
    return y_next

def main():
    io, y = read_outputs(expect_n=10000)
    ans = solve_next(y)
    io.sendline(str(ans).encode())
    try:
        print(io.recvall(timeout=5).decode(errors="ignore"))
    except Exception:
        pass

if __name__ == "__main__":
    main()