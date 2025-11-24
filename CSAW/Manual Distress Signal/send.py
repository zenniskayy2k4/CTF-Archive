#!/usr/bin/env python3
# collect_and_analyze.py
import requests, base64, time, argparse, hashlib
from collections import defaultdict

URL = "https://manual-distress.ctf.csaw.io/send"

def send(data):
    try:
        r = requests.post(URL, json={"data": data}, timeout=10)
        r.raise_for_status()
        j = r.json()
        return j
    except Exception as e:
        return {"error": str(e)}

def decode_b64_to_bytes(s):
    try:
        return base64.b64decode(s)
    except Exception:
        return None

def hexdump(b):
    return b.hex()

def shorthex(b, n=16):
    return b[:n].hex()

def sha1(b): return hashlib.sha1(b).hexdigest()

def main(n=200, pause=0.05):
    seen_full = {}
    seen_payload_hash = defaultdict(list)
    blobs = []
    for i in range(n):
        data = "probe#" + str(i)  # changeable; we can randomize more
        j = send(data)
        if "ciphertext" not in j:
            print(f"[{i}] no ciphertext, err:", j.get("error"))
            time.sleep(pause)
            continue
        ct_b64 = j["ciphertext"]
        b = decode_b64_to_bytes(ct_b64)
        if b is None:
            print(f"[{i}] base64 decode fail")
            continue
        L = len(b)
        # compute various hashes
        h_full = sha1(b)
        # payload excluding first 5 bytes header (header length =5)
        payload = b[5:]
        h_payload = sha1(payload)
        # store
        blobs.append((i, b, ct_b64))
        print(f"[{i}] got {L} bytes; full_sha1={h_full}; payload_sha1={h_payload}; first16={shorthex(b)}")
        # detect exact duplicates
        if h_full in seen_full:
            print("  -> exact duplicate found with index", seen_full[h_full])
        else:
            seen_full[h_full] = i
        # group by payload hash (to find reuse of explicit IV vs payload similarity)
        seen_payload_hash[h_payload].append(i)
        time.sleep(pause)
    # summary: any payload groups >1 ?
    reuse_groups = {k:v for k,v in seen_payload_hash.items() if len(v)>1}
    if reuse_groups:
        print("\nPossible payload reuse groups (payload after header identical):")
        for k,v in reuse_groups.items():
            print("  hash", k, "indices", v)
    else:
        print("\nNo payload-after-header exact reuse detected in this run.")
    # show constant positions across blobs (min length)
    if blobs:
        minL = min(len(b) for _,b,_ in blobs)
        const_pos = []
        for idx in range(minL):
            vals = {b[idx] for _,b,_ in blobs}
            if len(vals)==1:
                const_pos.append(idx)
        print("Constant byte positions across all blobs (first", minL, "bytes):", const_pos)

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--n", type=int, default=200)
    p.add_argument("--pause", type=float, default=0.03)
    args = p.parse_args()
    main(args.n, args.pause)
