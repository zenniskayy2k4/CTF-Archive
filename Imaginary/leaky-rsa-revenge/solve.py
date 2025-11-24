# solve_leaky_rsa_revenge_robust.py
import socket, json, sys
from hashlib import sha256
from binascii import unhexlify
from Crypto.Cipher import AES

HOST = "leaky-rsa-revenge.chal.imaginaryctf.org"
PORT = 1337
E = 65537

LOW_SKIP = 4         # tránh gửi lại c (t=0): bỏ 4 LSB để brute-force
GRAB_BITS = 512      # số bit thấp cần thu (>=128, 256; 512 an toàn)
MAX_ROUNDS = 2000    # dư dả

def recv_json_line(f):
    while True:
        line = f.readline()
        if not line:
            raise ConnectionError("Disconnected")
        s = line.decode(errors="ignore").strip()
        if not s:
            continue
        try:
            return json.loads(s)
        except json.JSONDecodeError:
            # banner/noise
            continue

def try_decrypt(iv, ct, key_bytes_list):
    tried = 0
    for key in key_bytes_list:
        tried += 1
        for mode_key in (("AES128", key[:16]), ("AES256", key[:32])):
            name, k = mode_key
            try:
                cipher = AES.new(k, AES.MODE_CBC, iv)
                pt = cipher.decrypt(ct)
            except Exception:
                continue
            # Heuristic nhận diện flag
            if any(tag in pt for tag in (b"ictf{", b"flag{", b"imaginary")):
                try:
                    print(f"[+] Hit with {name}, keylen={len(k)}")
                    print(pt.decode(errors="ignore"))
                except Exception:
                    print(pt)
                return True
    return False

def build_key_candidates(m_int, have_bits):
    """
    Sinh ra nhiều kiểu m_bytes/khoá ứng viên khả dĩ:
    - minimal big-endian
    - cố định 16/24/32 byte (MSB zero-pad hoặc cắt LSB/MSB)
    - cộng thêm biến thể băm sha256
    """
    out = []

    # Dựng từ phần bit thấp đã có: m_int chứa bit [LOW_SKIP .. GRAB_BITS-1]
    # Ta thêm 4 LSB brute-force
    low_mask = (1 << LOW_SKIP) - 1

    for low in range(1 << LOW_SKIP):
        full = (m_int | low)
        # Dạng big-endian tối thiểu
        mb = full.to_bytes((full.bit_length() + 7) // 8 or 1, "big")
        out.append(mb)

        # Định cỡ 16/24/32 byte theo 3 cách: pad MSB, cắt MSB, cắt LSB
        for size in (16, 24, 32):
            if len(mb) == size:
                out.append(mb)
            elif len(mb) < size:
                out.append(mb.rjust(size, b"\x00"))  # pad MSB zeros
            else:
                # Cắt MSB (giữ 16/24/32 byte thấp)
                out.append(mb[-size:])
                # Cắt LSB (giữ 16/24/32 byte cao)
                out.append(mb[:size])

    # Từ các mb, sinh thêm biến thể băm
    derived = []
    for mb in out:
        derived.append(mb)
        h = sha256(mb).digest()
        derived.append(h[:16])
        derived.append(h[:24])
        derived.append(h[:32])
    # Khử trùng lặp, ưu tiên ngắn trước
    uniq = []
    seen = set()
    for k in sorted(derived, key=len):
        if k not in seen:
            seen.add(k)
            uniq.append(k)
    return uniq

def main():
    s = socket.create_connection((HOST, PORT))
    f = s.makefile('rwb', buffering=0)

    # 1) Nhận n, c (RSA của m), iv, ct
    first = recv_json_line(f)
    if not all(k in first for k in ("n", "c", "iv", "ct")):
        print("Không lấy được n,c,iv,ct:", first); return
    n = int(first["n"])
    c0 = int(first["c"])
    iv = unhexlify(first["iv"])
    ct = unhexlify(first["ct"])

    # Precompute 2^(E*t) mod n cho t đủ dùng (tối đa ~ GRAB_BITS)
    max_t = GRAB_BITS + 16
    pow2e = [pow(2, E * t, n) for t in range(max_t + 1)]

    # Với mỗi lớp i∈{0,1,2,3}, ta sẽ xin lần lượt các bit j = i+LOW_SKIP, i+LOW_SKIP+4, ...
    next_target = [i + LOW_SKIP for i in range(4)]
    bits = [None] * GRAB_BITS
    need_total = GRAB_BITS - LOW_SKIP
    filled = 0

    rounds = 0
    while rounds < MAX_ROUNDS and filled < need_total:
        rounds += 1
        obj = recv_json_line(f)
        if "idx" not in obj:
            continue
        i = int(obj["idx"])

        j = next_target[i]
        if j >= GRAB_BITS:
            # Hết bit ở lớp này => gửi no-op để consume round
            t = max(LOW_SKIP, 8)
            cprime = (c0 * pow2e[t]) % n
            f.write(json.dumps({"c": cprime}).encode() + b"\n")
            _ = recv_json_line(f)
            continue

        t = j - i
        if t <= 0:
            # (không xảy ra với khởi tạo i+LOW_SKIP)
            t += 4 * ((-t)//4 + 1)
        if t > max_t:
            for tt in range(max_t + 1, t + 1):
                pow2e.append(pow(2, E * tt, n))
            max_t = t

        cprime = (c0 * pow2e[t]) % n
        if cprime == c0:
            # Hiếm; đẩy sang bit tiếp theo cùng lớp
            j += 4
            if j >= GRAB_BITS:
                t = max(LOW_SKIP, 8)
            else:
                t = j - i
            if t > max_t:
                for tt in range(max_t + 1, t + 1):
                    pow2e.append(pow(2, E * tt, n))
                max_t = t
            cprime = (c0 * pow2e[t]) % n

        f.write(json.dumps({"c": cprime}).encode() + b"\n")
        bobj = recv_json_line(f)
        if "b" not in bobj:
            continue
        b = int(bobj["b"])
        if b in (0, 1):
            if bits[j] is None:
                bits[j] = b
                filled += 1
            next_target[i] = j + 4

    # Kiểm tra đã đủ bit 4..GRAB_BITS-1
    for k in range(LOW_SKIP, GRAB_BITS):
        if bits[k] is None:
            print(f"[!] Thiếu bit {k}. Chạy lại lần nữa (do ngẫu nhiên idx/timeout).")
            return

    # Dựng integer từ các bit đã có
    m_low = 0
    for k in range(LOW_SKIP, GRAB_BITS):
        m_low |= (bits[k] << k)

    # Sinh danh sách khóa ứng viên và thử decrypt
    cands = build_key_candidates(m_low, GRAB_BITS - LOW_SKIP)
    print(f"[i] Thu được {GRAB_BITS-LOW_SKIP} bit thấp. Thử {len(cands)} khóa ứng viên…")
    if not try_decrypt(iv, ct, cands):
        print("[x] Chưa khớp. Chạy lại để thu thêm bit hoặc tác giả derive khóa khác lạ hơn.")
        # Gợi ý:
        # - tăng GRAB_BITS lên 768
        # - sửa build_key_candidates để thêm biến thể khác nếu cần

if __name__ == "__main__":
    main()
