# solve_zkpow_v2.py
# Robust solver for ImaginaryCTF "zkpow" that matches the provided verifier exactly.
# - Commits: sha256(b"vertex:" + str(v) + ":" + str(color) + ":" + nonce)
# - Merkle proof items: [sibling_hex, sibling_is_left]
# - Openings keys: vertex indices as strings
#
# It prepares the proof before the "proof:" prompt and sends immediately.
# Adds verbose output and handles servers that may or may not end lines with '\n'.

import socket, json, os, hashlib, sys, select

HOST = "zkpow.chal.imaginaryctf.org"
PORT = 1337
VERBOSE = True

def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def commit_prefix(v: int, c: int) -> bytes:
    return b"vertex:" + str(v).encode() + b":" + str(c).encode() + b":"

def build_merkle_levels(leaves_bytes):
    if not leaves_bytes:
        return [[sha256(b"")]]
    levels = [leaves_bytes]
    cur = leaves_bytes
    while len(cur) > 1:
        nxt = []
        i = 0
        n = len(cur)
        while i < n:
            left = cur[i]
            right = cur[i+1] if i+1 < n else left
            nxt.append(sha256(left + right))
            i += 2
        levels.append(nxt)
        cur = nxt
    return levels

def merkle_root_hex(levels):
    return levels[-1][0].hex()

def merkle_proof(levels, index):
    proof = []
    idx = index
    for level in levels[:-1]:
        n = len(level)
        if idx % 2 == 0:
            sib_index = idx + 1 if idx + 1 < n else idx
            sibling = level[sib_index]
            proof.append([sibling.hex(), False])  # sibling on right
        else:
            sib_index = idx - 1
            sibling = level[sib_index]
            proof.append([sibling.hex(), True])   # sibling on left
        idx //= 2
    return proof

def fiat_shamir_index(root_hex, m):
    return int.from_bytes(hashlib.sha256(root_hex.encode()).digest(), "big") % m

def prepare_proof(n, edges):
    colors = [v % 3 for v in range(n)]
    prefixes = [commit_prefix(v, colors[v]) for v in range(n)]
    tries = 0
    while True:
        tries += 1
        nonces = [os.urandom(16) for _ in range(n)]
        leaves = [sha256(prefixes[v] + nonces[v]) for v in range(n)]
        levels = build_merkle_levels(leaves)
        root_hex = merkle_root_hex(levels)
        idx = fiat_shamir_index(root_hex, len(edges))
        u, v = edges[idx]
        if colors[u] != colors[v]:
            proof = {
                "merkle_root": root_hex,
                "openings": {
                    str(u): {
                        "color": colors[u],
                        "nonce": nonces[u].hex(),
                        "merkle_proof": merkle_proof(levels, u),
                    },
                    str(v): {
                        "color": colors[v],
                        "nonce": nonces[v].hex(),
                        "merkle_proof": merkle_proof(levels, v),
                    },
                },
            }
            return proof, tries, (u, v), idx

def run(host, port):
    s = socket.create_connection((host, port))
    s.settimeout(10.0)
    buf = b""
    prepared = None
    n = None
    edges = None
    rounds = 0

    def flush_recv():
        nonlocal buf
        out = b""
        # Read whatever is available without blocking too long
        ready, _, _ = select.select([s], [], [], 0.05)
        while ready:
            chunk = s.recv(4096)
            if not chunk:
                break
            out += chunk
            ready, _, _ = select.select([s], [], [], 0.01)
        if out:
            buf += out
            if VERBOSE:
                try:
                    sys.stdout.write(out.decode("utf-8", "ignore"))
                    sys.stdout.flush()
                except:
                    pass

    try:
        while True:
            flush_recv()
            # Try to extract lines from buffer
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                text = line.decode("utf-8", "ignore").strip()
                if not text:
                    continue

                # Try parse JSON graph line
                if text.startswith("{") and '"edges"' in text:
                    try:
                        obj = json.loads(text)
                        n = obj["n"]
                        edges = obj["edges"]
                        prepared = None
                        # Precompute immediately
                        prepared = prepare_proof(n, edges)
                        if VERBOSE and prepared:
                            _, tries, (u,v), idx = prepared
                            # print(f"[debug] prepared in {tries} tries, selected edge idx={idx} ({u},{v}), colors OK")
                    except Exception as e:
                        if VERBOSE:
                            print(f"[warn] JSON parse error: {e}")

                # Detect prompt lines that include 'proof:' even if followed on same line
                if "proof:" in text.lower():
                    if prepared is None and n is not None and edges is not None:
                        prepared = prepare_proof(n, edges)
                    if prepared is not None:
                        proof_obj, _, _, _ = prepared
                        payload = json.dumps(proof_obj) + "\n"
                        s.sendall(payload.encode())
                        rounds += 1
                        prepared = None

            # If server sent a prompt without newline, search raw buffer
            if b"proof:" in buf.lower():
                # If prompt sits in buffer without newline, still send
                if prepared is None and n is not None and edges is not None:
                    prepared = prepare_proof(n, edges)
                if prepared is not None:
                    proof_obj, _, _, _ = prepared
                    payload = json.dumps(proof_obj) + "\n"
                    s.sendall(payload.encode())
                    rounds += 1
                    prepared = None
                    # remove the prompt token to avoid re-sending
                    buf = buf.replace(b"proof:", b"", 1)

            # Exit if socket closes
            ready, _, _ = select.select([s], [], [], 0.05)
            if not ready and not buf:
                # peek to check if connection closed
                try:
                    s.settimeout(0.0)
                    data = s.recv(1)
                    if not data:
                        break
                    else:
                        buf += data
                except BlockingIOError:
                    pass
                finally:
                    s.settimeout(10.0)

    finally:
        s.close()
    return rounds

if __name__ == "__main__":
    host = HOST if len(sys.argv) < 2 else sys.argv[1]
    port = PORT if len(sys.argv) < 3 else int(sys.argv[2])
    try:
        total = run(host, port)
        print(f"[+] Completed {total} rounds (I/O).")
    except KeyboardInterrupt:
        print("\n[!] Aborted by user.")
