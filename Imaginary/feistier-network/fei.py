#!/usr/bin/env python3
# Feistier client: auto PoW + menu 1/2 + CSV logging (Windows/WSL/Linux)
import socket, re, base64, sys, time, csv, os, argparse

HOST, PORT = "feistier-network.chal.imaginaryctf.org", 1337
P = (1 << 1279) - 1  # kCTF PoW modulus

def _dec_num(enc: str) -> int:
    return int.from_bytes(base64.b64decode(enc.encode()), "big")
def _enc_num(num: int) -> str:
    size = (num.bit_length() // 24) * 3 + 3
    return base64.b64encode(num.to_bytes(size, "big")).decode()

def solve_pow_from_banner(banner: str) -> str:
    m = re.search(r"solve\s+(s\.[A-Za-z0-9+/=\.]+)", banner)
    if not m: raise RuntimeError("Không thấy token PoW.")
    s_tok = m.group(1).split(".")
    diff = _dec_num(s_tok[1]); x = _dec_num(s_tok[2])
    e = (P + 1)//4
    for _ in range(diff):
        x = pow(x, e, P) ^ 1
    return "s." + _enc_num(x)

def recv_until(sock, needles, timeout=20):
    sock.settimeout(0.5)
    buf = b''; start = time.time()
    while True:
        try:
            chunk = sock.recv(65536)
            if not chunk: return buf.decode(errors="ignore")
            buf += chunk
            text = buf.decode(errors="ignore")
            sys.stdout.write(chunk.decode(errors="ignore")); sys.stdout.flush()
            if any(n in text for n in needles): return text
        except socket.timeout:
            pass
        if time.time()-start > timeout:
            return buf.decode(errors="ignore")

def connect_pow():
    s = socket.create_connection((HOST, PORT))
    banner = recv_until(s, ["Solution?"], timeout=30)
    sol = solve_pow_from_banner(banner)
    s.sendall((sol+"\n").encode())
    _ = recv_until(s, ["Correct", "give me your best shot"], timeout=10)
    return s

def b64seed(n: int) -> str:
    if n == 0: b = b"\x00"
    else:
        l = (n.bit_length()+7)//8
        b = n.to_bytes(l, "big")
    return base64.b64encode(b).decode()

def do_print_flag(s, seed_b64: str) -> str:
    s.sendall((seed_b64+"\n").encode())
    _ = recv_until(s, ["1) print flag", "2) print custom message"], timeout=5)
    s.sendall(b"1\n")
    out = recv_until(s, [">:)", "give me your best shot", "don't try and break me"], timeout=5)
    m = re.findall(r"[A-Za-z0-9+/=]{40,}", out)
    if not m: raise RuntimeError("Không tìm thấy ciphertext flag.")
    return m[-1]

def do_encrypt(s, seed_b64: str, msg_bytes: bytes) -> str:
    s.sendall((seed_b64+"\n").encode())
    _ = recv_until(s, ["1) print flag", "2) print custom message"], timeout=5)
    s.sendall(b"2\n")
    _ = recv_until(s, ["sure what's the message"], timeout=5)
    msg_b64 = base64.b64encode(msg_bytes).decode()
    s.sendall((msg_b64+"\n").encode())
    out = recv_until(s, [">:)", "give me your best shot", "don't try and break me"], timeout=5)
    m = re.findall(r"[A-Za-z0-9+/=]{40,}", out)
    if not m: raise RuntimeError("Không thấy ciphertext.")
    return m[-1]

def cmd_oneshot(seed: int, mode: str, msg_hex: str = None):
    s = connect_pow()
    try:
        seed_b64 = b64seed(seed)
        if mode == "flag":
            c = do_print_flag(s, seed_b64)
            print(f"\n[FLAG-CIPHERTEXT] seed={seed} -> {c}")
        else:
            msg = bytes.fromhex(msg_hex) if msg_hex else b""
            if len(msg) > 64: raise SystemExit("Thông điệp >64 bytes.")
            c = do_encrypt(s, seed_b64, msg)
            print(f"\n[ORACLE] seed={seed} msg={msg.hex()} -> {c}")
    finally:
        s.close()

def cmd_collect(start: int, count: int, path: str):
    s = connect_pow()
    rows = []; wrote = 0
    try:
        for n in range(start, start+count):
            seed_b64 = b64seed(n)
            try:
                c = do_print_flag(s, seed_b64)
                rows.append({"seed": n, "cipher_b64": c})
                print(f"[+] seed {n}: {c}")
            except Exception as e:
                print(f"[x] seed {n} lỗi: {e}; reconnect…")
                s.close()
                s = connect_pow()
            if len(rows) >= 200:
                wrote += _flush_csv(path, rows); rows = []
        if rows: wrote += _flush_csv(path, rows)
        print(f"[*] Ghi {wrote} dòng vào {path}")
    finally:
        s.close()

def _flush_csv(path, rows):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    hdr = not os.path.exists(path)
    with open(path, "a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["seed","cipher_b64"])
        if hdr: w.writeheader()
        w.writerows(rows)
    return len(rows)

def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    p1 = sub.add_parser("oneshot"); p1.add_argument("--seed", type=int, required=True)
    p1.add_argument("--mode", choices=["flag","enc"], default="flag")
    p1.add_argument("--msg-hex", help="Hex message (<=64 bytes) khi mode=enc")
    p2 = sub.add_parser("collect"); p2.add_argument("--start", type=int, default=1)
    p2.add_argument("--count", type=int, default=1000); p2.add_argument("--csv", default="collected.csv")
    args = ap.parse_args()
    if args.cmd=="oneshot": cmd_oneshot(args.seed, args.mode, args.msg_hex)
    else: cmd_collect(args.start, args.count, args.csv)

if __name__ == "__main__":
    main()
