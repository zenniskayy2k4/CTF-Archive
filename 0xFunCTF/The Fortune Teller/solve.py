from pwn import remote
from z3 import (
    BitVec, BitVecVal, Extract, SolverFor, sat,
    LShR, ZeroExt
)
import re

HOST = "chall.0xfun.org"
PORT = 56792

MASK = 1 << 64
A = 2862933555777941757
C = 3037000493


def recv_banner(io, max_bytes=20000, timeout=5):
    io.timeout = timeout
    data = b""
    while len(data) < max_bytes:
        chunk = io.recv(4096, timeout=timeout)
        if not chunk:
            break
        data += chunk
        if b"predict" in data.lower() and b"state" in data.lower():
            break
    return data


def parse_glimpses(text: str):
    out = []
    for line in text.splitlines():
        line = line.strip()
        if re.fullmatch(r"-?\d+", line):
            out.append(int(line))
            continue
        m = re.search(r"glimpse.*?(-?\d+)\s*$", line, flags=re.IGNORECASE)
        if m:
            out.append(int(m.group(1)))
    return out


def pcg32_output(oldstate64):
    # PCG-XSH-RR 64->32 (canonical)
    x = LShR(oldstate64, 18) ^ oldstate64
    x = LShR(x, 27)
    x32 = Extract(31, 0, x)

    rot5 = Extract(4, 0, LShR(oldstate64, 59))
    rot = ZeroExt(27, rot5)  # 32-bit shift amount

    r = LShR(x32, rot)
    l = x32 << ((BitVecVal(32, 32) - rot) & BitVecVal(31, 32))
    return r | l


def recover_state_after(glimpses, inc_value, mode: str):
    seed = BitVec("seed", 64)
    a = BitVecVal(A, 64)
    inc = BitVecVal(inc_value % MASK, 64)

    solver = SolverFor("QF_BV")
    solver.set(timeout=20000)

    st = seed  # internal 64-bit state
    for g in glimpses:
        g_u32 = g & 0xFFFFFFFF
        g_bv = BitVecVal(g_u32, 32)

        if mode == "high32_post":
            st = a * st + inc
            solver.add(Extract(63, 32, st) == g_bv)

        elif mode == "low32_post":
            st = a * st + inc
            solver.add(Extract(31, 0, st) == g_bv)

        elif mode == "high32_pre":
            solver.add(Extract(63, 32, st) == g_bv)
            st = a * st + inc

        elif mode == "low32_pre":
            solver.add(Extract(31, 0, st) == g_bv)
            st = a * st + inc

        elif mode == "pcg32_oldstate":
            solver.add(pcg32_output(st) == g_bv)
            st = a * st + inc

        elif mode == "pcg32_newstate":
            st = a * st + inc
            solver.add(pcg32_output(st) == g_bv)

        else:
            raise ValueError("unknown mode")

    if solver.check() != sat:
        return None

    model = solver.model()
    seed_val = model[seed].as_long()
    state_after_val = model.eval(st, model_completion=True).as_long()
    return seed_val, state_after_val


def predict_next_full_states(state_after_k, inc_value, n=5):
    s = state_after_k
    out = []
    for _ in range(n):
        s = (A * s + (inc_value % MASK)) % MASK
        out.append(s)
    return out


def solve():
    io = remote(HOST, PORT)
    banner = recv_banner(io, timeout=5).decode(errors="replace")
    print("[Server output]\n" + banner)

    glimpses = parse_glimpses(banner)
    print(f"[*] Parsed {len(glimpses)} glimpses: {glimpses}")

    if len(glimpses) < 3:
        print("[-] Need at least 3 glimpses.")
        io.close()
        return

    inc_variants = [
        ("inc=C", C),
        ("inc=(C<<1)|1", (C << 1) | 1),
    ]

    modes = [
        "high32_post", "low32_post", "high32_pre", "low32_pre",
        "pcg32_oldstate", "pcg32_newstate",
    ]

    found = None
    for inc_name, inc_val in inc_variants:
        for mode in modes:
            res = recover_state_after(glimpses, inc_val, mode)
            if res is not None:
                seed_val, state_after = res
                found = (inc_name, inc_val, mode, seed_val, state_after)
                break
        if found:
            break

    if not found:
        print("[-] Still UNSAT for all modes/inc variants.")
        io.close()
        return

    inc_name, inc_val, mode, seed_val, state_after = found
    print(f"[+] Found model: {inc_name}, mode={mode}")
    print(f"[+] seed = {seed_val}")
    print(f"[+] state_after_glimpses = {state_after}")

    preds = predict_next_full_states(state_after, inc_val, n=5)
    payload = " ".join(str(x) for x in preds)
    print(f"[*] Sending: {payload}")

    io.sendline(payload.encode())
    io.interactive()


if __name__ == "__main__":
    solve()