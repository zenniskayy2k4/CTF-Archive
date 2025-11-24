#!/usr/bin/env python3
# scan_decode.py
import os,re,base64,codecs
from pathlib import Path

EXTS = [".js", ".html", ".css", ".json", ".txt"]
root = Path(".")
files = [p for p in root.iterdir() if p.is_file() and any(str(p).endswith(e) for e in EXTS)]

print("[*] Files to scan:", len(files))
candidates = []

# 1) find quoted long strings that look like base64 or hex or ascii lists
b64_re = re.compile(r'["\']([A-Za-z0-9+/]{20,}={0,2})["\']')
hex_re = re.compile(r'["\'](0x[0-9a-fA-F]{6,}|[0-9a-fA-F]{40,})["\']')
parts_re = re.compile(r'\[(?:["\'][^"\']{1,6}["\'],\s*){3,}["\'][^"\']{1,6}["\']\]')  # array of small strings

for p in files:
    txt = p.read_text(errors='ignore')
    for m in b64_re.finditer(txt):
        s = m.group(1)
        candidates.append(("base64", str(p), s))
    for m in hex_re.finditer(txt):
        s = m.group(1)
        candidates.append(("hex", str(p), s))
    for m in parts_re.finditer(txt):
        s = m.group(0)
        candidates.append(("parts", str(p), s[:200]))

print("[*] Found candidates:", len(candidates))

def try_base64(s):
    try:
        b = base64.b64decode(s, validate=True)
        if any(32 <= c < 127 for c in b):  # printable
            return b.decode('utf-8', errors='ignore')
    except Exception:
        return None

def try_hex(s):
    try:
        s2 = s
        if s2.startswith("0x") or s2.startswith("0X"):
            s2 = s2[2:]
        if len(s2) % 2 == 1:
            s2 = '0' + s2
        b = bytes.fromhex(s2)
        if any(32 <= c < 127 for c in b):
            return b.decode('utf-8', errors='ignore')
    except Exception:
        return None

def try_rot13(s):
    try:
        return codecs.decode(s, 'rot_13')
    except Exception:
        return None

def try_xor(b, key):
    return bytes([c ^ key for c in b])

out_matches = []

for typ, fname, s in candidates:
    print("----", typ, fname, s[:120])
    if typ == "base64":
        decoded = try_base64(s)
        if decoded:
            print("  [base64-decoded]:", decoded[:300])
            out_matches.append((fname, s, decoded))
    elif typ == "hex":
        d = try_hex(s)
        if d:
            print("  [hex-decoded]:", d[:300])
            out_matches.append((fname, s, d))
    elif typ == "parts":
        # attempt to eval array-of-strings and join
        try:
            arr = eval(s)  # safe-ish inside local scanning context
            if isinstance(arr, list):
                candidate = "".join(arr)
                print("  [joined parts]:", candidate[:300])
                out_matches.append((fname, s, candidate))
        except Exception:
            pass

# Heuristic: try brute-forcing short xor keys on all files (first 2000 bytes)
print("\n[*] Brute XOR small keys on files (scan first 2000 bytes for printable marker like 'CTF'/'wat'/'flag')\n")
for p in files:
    b = p.read_bytes()[:2000]
    for key in range(1, 64):
        xb = try_xor(b, key)
        try:
            st = xb.decode('utf-8', errors='ignore')
        except:
            st = None
        if st and (re.search(r'watctf|flag\{|\bCTF\{|\bFLAG\{', st, re.I)):
            print("XOR key", key, "hit in", p)
            context = re.search(r'(.{0,60}(watctf|flag\{|CTF\{).{0,60})', st, re.I)
            print(" ->", context.group(0) if context else st[:200])
            out_matches.append((str(p), f"xor_{key}", context.group(0) if context else st[:200]))

if out_matches:
    print("\n== Possible decoded outputs ==")
    for m in out_matches:
        print(m[0], m[1], "\n", m[2][:500], "\n---")
else:
    print("No obvious decodes found. Paste suspicious lines here and I'll help decode.")
