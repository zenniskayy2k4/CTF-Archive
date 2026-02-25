import re
import os
import base64
import binascii
import gzip
import zlib
import bz2
import lzma
import zipfile
import io
from collections import Counter
from typing import List, Tuple

FILE_PATH = "notes.txt"


def pct_len(lengths: List[int], q: float) -> int:
    if not lengths:
        return 0
    s = sorted(lengths)
    idx = int((len(s) - 1) * q)
    return s[idx]


def extract_payload_from_line(line: bytes) -> bytes:
    chunks = re.findall(rb"[ -~]{16,}", line)
    if not chunks:
        return b""          # <-- đổi: không có chunk thì bỏ dòng này
    return max(chunks, key=len)


def samples_from_lines(blob: bytes) -> List[bytes]:
    lines = [ln for ln in blob.splitlines() if ln.strip(b"\r\n\t ")]
    if len(lines) < 5:
        return []

    out = []
    for ln in lines:
        p = extract_payload_from_line(ln.rstrip(b"\r\n"))
        if p and len(p) >= 64:   # quan trọng: bỏ mấy dòng “rác” quá ngắn
            out.append(p)
    return out


def samples_from_printable_runs(blob: bytes, min_len: int = 64) -> List[bytes]:
    runs = re.findall(rb"[ -~]{%d,}" % min_len, blob)
    # lọc bớt rác: bỏ run toàn là '-' '_' etc nếu muốn; tạm giữ đơn giản
    return [r.strip() for r in runs if r.strip()]


def score_record_len(blob: bytes, rec_len: int, max_recs: int = 200) -> float:
    n = len(blob) // rec_len
    if n < 8:
        return -1.0
    n = min(n, max_recs)
    recs = [blob[i * rec_len:(i + 1) * rec_len] for i in range(n)]
    # điểm: trung bình tỉ lệ bit-majority mạnh (gần 1.0 là tốt)
    score = 0.0
    for i in range(rec_len):
        col = [r[i] for r in recs]
        if not col:
            continue
        # đo “độ đồng thuận” byte (nhanh)
        best = Counter(col).most_common(1)[0][1]
        score += best / len(col)
    return score / rec_len


def samples_from_fixed_records(blob: bytes) -> Tuple[List[bytes], int]:
    # thử đoán rec_len bằng cách quét một dải độ dài hợp lý
    best_len = 0
    best_score = -1.0

    # giới hạn để chạy nhanh
    max_len = min(8192, max(64, len(blob) // 8))
    for rec_len in range(64, max_len + 1, 8):
        n = len(blob) // rec_len
        if n < 8 or n > 50000:
            continue
        s = score_record_len(blob, rec_len)
        if s > best_score:
            best_score = s
            best_len = rec_len

    if best_len == 0:
        return ([], 0)

    n = len(blob) // best_len
    recs = [blob[i * best_len:(i + 1) * best_len] for i in range(n)]
    return (recs, best_len)


def majority_vote_bits(samples: List[bytes]) -> bytes:
    lengths = [len(s) for s in samples]
    # dùng 90th percentile để tránh mode bị “cụt”
    target_len = pct_len(lengths, 0.90)
    if target_len < 16:
        target_len = max(lengths)

    out = bytearray()
    for i in range(target_len):
        col = [s[i] for s in samples if len(s) > i]
        if len(col) < 3:
            out.append(0)
            continue

        byte_val = 0
        for bit in range(7):  # chỉ vote 0..6, bit7 luôn 0
            ones = sum((b >> bit) & 1 for b in col)
            if ones * 2 > len(col):
                byte_val |= (1 << bit)
        out.append(byte_val)

    return bytes(out)


def column_vote(samples: List[bytes], allowed: set[int], min_support: int, stop_after: int = 24) -> bytes:
    max_len = max(len(s) for s in samples)
    out = bytearray()
    low = 0

    for i in range(max_len):
        col = [s[i] for s in samples if len(s) > i and s[i] in allowed]
        if len(col) < min_support:
            low += 1
            if low >= stop_after:
                break
            continue

        low = 0
        out.append(Counter(col).most_common(1)[0][0])

    return bytes(out)


def peel_layers(data: bytes, max_steps: int = 80) -> bytes:
    cur = data

    for _ in range(max_steps):
        changed = False
        s = cur.strip()

        # --- decompress by magic ---
        if s.startswith(b"\x1f\x8b\x08"):
            cur = gzip.decompress(s); changed = True
        elif s.startswith(b"BZh"):
            cur = bz2.decompress(s); changed = True
        elif s.startswith(b"\xfd7zXZ\x00"):
            cur = lzma.decompress(s); changed = True
        elif len(s) >= 2 and s[0] == 0x78 and s[1] in (0x01, 0x9C, 0xDA):
            try:
                cur = zlib.decompress(s); changed = True
            except Exception:
                pass
        elif s.startswith(b"PK\x03\x04"):
            try:
                with zipfile.ZipFile(io.BytesIO(s)) as zf:
                    names = [n for n in zf.namelist() if not n.endswith("/")]
                    if names:
                        cur = zf.read(names[0])
                        changed = True
            except Exception:
                pass

        if changed:
            continue

        # --- ascii armors (ưu tiên base64 trước để tránh a85 decode nhầm) ---
        # base64 / urlsafe (tự pad '=' nếu thiếu)
        if re.fullmatch(rb"[A-Za-z0-9+/=\r\n]+", s):
            ss = s.replace(b"\r", b"").replace(b"\n", b"")
            ss += b"=" * ((4 - (len(ss) % 4)) % 4)
            try:
                cur = base64.b64decode(ss)
                changed = True
            except Exception:
                pass

        if changed:
            continue

        if re.fullmatch(rb"[A-Za-z0-9_\-=\r\n]+", s):
            ss = s.replace(b"\r", b"").replace(b"\n", b"")
            ss += b"=" * ((4 - (len(ss) % 4)) % 4)
            try:
                cur = base64.urlsafe_b64decode(ss)
                changed = True
            except Exception:
                pass

        if changed:
            continue

        # hex
        if len(s) % 2 == 0 and re.fullmatch(rb"[0-9a-fA-F]+", s):
            try:
                cur = binascii.unhexlify(s)
                changed = True
            except Exception:
                pass

        if changed:
            continue

        # ascii85: chỉ thử mạnh khi có wrapper <~ ~>
        if b"<~" in s:
            try:
                cur = base64.a85decode(s, adobe=True, ignorechars=b" \t\r\n")
                changed = True
            except Exception:
                pass
        else:
            # non-adobe a85: thử nhẹ nhàng, nhưng chỉ khi KHÔNG giống base64
            if not re.fullmatch(rb"[A-Za-z0-9+/=\r\n]+", s) and not re.fullmatch(rb"[A-Za-z0-9_\-=\r\n]+", s):
                try:
                    cur = base64.a85decode(s, adobe=False, ignorechars=b" \t\r\n")
                    changed = True
                except Exception:
                    pass

        if not changed:
            break

    return cur


def find_flag(data: bytes) -> str | None:
    text = data.decode("utf-8", errors="ignore")
    m = re.search(r"0xfun\{[^}\n]+\}", text)
    return m.group(0) if m else None


def brute_single_byte_xor_find_flag(data: bytes) -> tuple[int, str] | None:
    for k in range(256):
        x = bytes(b ^ k for b in data)
        flag = find_flag(x)
        if flag:
            return k, flag
    return None


PRINT_OK = set(range(32, 127)) | {9, 10, 13}  # space..~ + \t \n \r

def hex_head(b: bytes, n: int = 32) -> str:
    return b[:n].hex()

def crack_repeating_xor_with_crib(data: bytes, crib: bytes = b"0xfun{", max_key_len: int = 32) -> tuple[bytes, str] | None:
    """
    Thử XOR lặp với key_len 1..max_key_len.
    - Quét mọi vị trí start đặt crib vào
    - Byte key nào suy ra được thì cố định
    - Byte key còn thiếu: chọn k sao cho plaintext printable nhiều nhất
    """
    n = len(data)
    if n < len(crib):
        return None

    for key_len in range(1, max_key_len + 1):
        for start in range(0, n - len(crib) + 1):
            key = [None] * key_len
            ok = True

            # gán các byte key suy ra từ crib
            for j, ch in enumerate(crib):
                idx = (start + j) % key_len
                kb = data[start + j] ^ ch
                if key[idx] is None:
                    key[idx] = kb
                elif key[idx] != kb:
                    ok = False
                    break
            if not ok:
                continue

            # điền các byte key chưa biết bằng cách tối đa hóa printable
            for i in range(key_len):
                if key[i] is not None:
                    continue
                positions = [p for p in range(n) if (p % key_len) == i]
                best_k = 0
                best_score = -1
                for k in range(256):
                    score = 0
                    for p in positions:
                        if (data[p] ^ k) in PRINT_OK:
                            score += 1
                    if score > best_score:
                        best_score = score
                        best_k = k
                key[i] = best_k

            key_bytes = bytes(key)
            pt = bytes(data[i] ^ key_bytes[i % key_len] for i in range(n))
            flag = find_flag(pt)
            if flag:
                return key_bytes, flag

    return None


def main():
    blob = open(FILE_PATH, "rb").read()
    print(f"[*] notes size: {len(blob)} bytes")

    samples = samples_from_lines(blob)
    source = "lines"

    if len(samples) < 5:
        samples = samples_from_printable_runs(blob, min_len=64)
        source = "printable-runs"

    if len(samples) < 5:
        recs, rec_len = samples_from_fixed_records(blob)
        if recs:
            samples = recs
            source = f"fixed-records(len={rec_len})"

    if len(samples) < 5:
        print("[!] Không đủ samples để vote.")
        print("    first16:", blob[:16])
        return

    lens = [len(x) for x in samples]
    print(f"[*] samples source: {source}, count={len(samples)}")
    print(f"[*] sample lengths: min={min(lens)} p50={pct_len(lens,0.5)} p90={pct_len(lens,0.9)} max={max(lens)}")

    # vote theo alphabet trên TOÀN BỘ samples (không filter theo length nữa)
    B64 = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
    B64URL = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=")
    A85 = set(range(33, 118))  # '!'..'u'
    PRINT = set(range(32, 127))  # general printable ASCII

    min_support = max(20, min(300, len(samples) // 200))  # ~50 nếu có 10k samples
    print(f"[*] min_support: {min_support}")

    candidates = []
    for name, allowed in [("print", PRINT), ("b64", B64), ("b64url", B64URL), ("a85", A85)]:
        r = column_vote(samples, allowed, min_support=min_support, stop_after=200)
        print(f"[*] recovered({name}) len={len(r)} head={r[:48]!r}")
        candidates.append((name, r))

    # ưu tiên thử b64/b64url/a85 trước, print để cuối
    order = {"b64": 0, "b64url": 1, "a85": 2, "print": 3}
    candidates.sort(key=lambda t: order.get(t[0], 99))

    best = None
    for name, recovered in candidates:
        if not recovered:
            continue

        open(f"recovered_{name}.bin", "wb").write(recovered)

        peeled = peel_layers(recovered)
        open(f"peeled_{name}.bin", "wb").write(peeled)

        # 1) tìm trực tiếp
        flag = find_flag(peeled) or find_flag(recovered)
        if flag:
            print("[+] FLAG:", flag)
            print(f"[*] source candidate: {name}")
            return

        # 2) brute XOR 1-byte trên peeled (rất hay gặp sau base64)
        res = brute_single_byte_xor_find_flag(peeled)
        if res:
            k, flag = res
            print("[+] FLAG:", flag)
            print(f"[*] source candidate: {name}, xor_key=0x{k:02x}")
            return

        print(f"[*] {name}: recovered_len={len(recovered)} peeled_len={len(peeled)} peeled_hex_head={hex_head(peeled, 32)}")

        # 3) crack XOR lặp theo crib "0xfun{"
        res2 = crack_repeating_xor_with_crib(peeled, crib=b"0xfun{", max_key_len=32)
        if res2:
            key_bytes, flag = res2
            print("[+] FLAG:", flag)
            print(f"[*] source candidate: {name}, repeating_xor_key={key_bytes.hex()}")
            return

        # fallback: chấm best để debug
        score = len(peeled)
        if best is None or score > best[0]:
            best = (score, name, recovered, peeled)

    if best:
        score, name, recovered, peeled = best
        print(f"[!] Chưa thấy flag. Best candidate={name}, peeled_len={score}")
        print("    recovered head:", recovered[:64])
        print("    peeled head   :", peeled[:64])
    else:
        print("[!] Không có candidate nào recover được.")
        
if __name__ == "__main__":
    main()