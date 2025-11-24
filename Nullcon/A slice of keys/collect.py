# collector.py
import socket, re, json, random, time
from math import gcd

HOST = "52.59.124.14"
PORT = 5103
E = 1337
MAX_QUERIES = 1200   # tăng lên để thu đủ mẫu (tùy server cho phép)

def recv_until(sock, patt=b"\n"):
    data = b""
    while True:
        ch = sock.recv(1)
        if not ch: break
        data += ch
        if data.endswith(patt): break
    return data

def recv_all(sock, timeout=0.2):
    sock.settimeout(timeout)
    out = b""
    try:
        while True:
            out += sock.recv(4096)
    except Exception:
        pass
    return out

def send_line(sock, s):
    if isinstance(s, str): s = s.encode()
    sock.sendall(s + b"\n")

class Oracle:
    def __init__(self, sock):
        self.s = sock
        self.used = 0
    def enc(self,m):
        self.used += 1
        send_line(self.s, f"e:{m}")
        out = recv_until(self.s, b"\n").strip()
        # attempt to parse integer lines until we get a number
        while not re.fullmatch(rb"-?\d+", out):
            more = recv_until(self.s, b"\n").strip()
            if re.fullmatch(rb"-?\d+", more):
                out = more
                break
            out = more
        return int(out)
    def dec(self,m):
        self.used += 1
        send_line(self.s, f"d:{m}")
        out = recv_until(self.s, b"\n").strip()
        while not re.fullmatch(rb"-?\d+", out):
            more = recv_until(self.s, b"\n").strip()
            if re.fullmatch(rb"-?\d+", more):
                out = more
                break
            out = more
        return int(out)

def recover_n_from_encrypt(oracle, tries=12):
    # gcd trick using encrypt oracle
    vals = []
    for _ in range(tries):
        m = random.randrange(2, 1<<60)
        r = oracle.enc(m)
        vals.append(abs(pow(m, E) - r))
    g = 0
    for v in vals:
        g = gcd(g, v)
    return g

def main():
    s = socket.create_connection((HOST, PORT))
    banner = recv_until(s, b"\n").decode(errors="ignore").strip()
    # read further lines
    banner += "\n" + recv_all(s, 0.3).decode(errors="ignore")
    # find hex line
    ct_hex = None
    for line in banner.splitlines():
        if re.fullmatch(r"[0-9a-fA-F]+", line.strip()):
            ct_hex = line.strip()
            break
    if not ct_hex:
        print("Cannot find ciphertext.")
        print(banner); return
    print("[+] Ciphertext:", ct_hex)
    oracle = Oracle(s)
    print("[*] Recovering n...")
    n = recover_n_from_encrypt(oracle, tries=18)
    print("[+] Recovered n with bitlen:", n.bit_length())
    # Now collect many dec samples
    samples = []
    queries_left = MAX_QUERIES
    # we must be careful; the server prints prompt after each response. We'll collect until we hit budget/limit.
    for i in range(1, MAX_QUERIES+1):
        m = random.randrange(2, n-1)
        try:
            r = oracle.dec(m)
        except Exception as ex:
            print("Exception on dec:", ex)
            break
        samples.append([m, r])
        if i % 50 == 0:
            print(f"Collected {i} samples")
        time.sleep(0.02)
    # Save
    with open("oracle_data.json","w") as f:
        json.dump({"n": str(n), "e": E, "ct_hex": ct_hex, "samples": [[str(m), str(r)] for m,r in samples]}, f)
    print("[+] Dumped oracle_data.json with", len(samples), "samples")
    s.close()

if __name__ == "__main__":
    main()
