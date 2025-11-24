#!/usr/bin/env python3
# exploit_try_formats.py
# Try many input formats (hex, 0xhex, base64, decimal big-int, raw) for sign/get_flag.

import os, sys, time, base64, argparse, re
try:
    from pwn import remote, context
    context.log_level = 'error'
    USE_PWN = True
except Exception:
    import socket
    USE_PWN = False

try:
    from Crypto.Cipher import AES
except Exception:
    AES = None

HOST = "crypto1.cscv.vn"
PORT = 1337

def connect():
    if USE_PWN:
        return remote(HOST, PORT, timeout=8)
    else:
        s = socket.create_connection((HOST, PORT), timeout=8)
        return s

def recv_all(s, timeout=0.2):
    if USE_PWN:
        try:
            return s.recv(timeout=timeout)
        except Exception:
            return b''
    else:
        s.settimeout(timeout)
        try:
            return s.recv(4096)
        except Exception:
            return b''

def sendline(s, data):
    if isinstance(data, str):
        data = data.encode()
    if USE_PWN:
        s.sendline(data)
    else:
        s.sendall(data + b'\n')

def craft_gcm(key_bytes, plaintext=b"admin = True"):
    if AES is None:
        raise RuntimeError("pycryptodome required (pip install pycryptodome)")
    nonce = os.urandom(12)
    cipher = AES.new(key_bytes, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(plaintext)
    return nonce + ct + tag

def bytes_to_decimal_str(b):
    return str(int.from_bytes(b, byteorder='big'))

def try_formats_for_sign_and_flag(fk_key_hex):
    fk_key = bytes.fromhex(fk_key_hex)
    pt = b"user=attacker;admin = True;note=ctf"
    enc = craft_gcm(fk_key, pt)  # nonce|ct|tag

    # possible enc representations
    enc_formats = []
    enc_formats.append(("raw", enc))  # raw bytes (if pwntools)
    enc_formats.append(("hex", enc.hex()))
    enc_formats.append(("0xhex", "0x" + enc.hex()))
    enc_formats.append(("b64", base64.b64encode(enc).decode()))
    enc_formats.append(("dec", bytes_to_decimal_str(enc)))

    sig_formats_to_try = ["hex", "b64", "dec"]

    results = []

    for name, enc_repr in enc_formats:
        s = connect()
        time.sleep(0.05)
        banner = recv_all(s, timeout=0.2)
        # rotate? assume already done by user or we don't need to rotate here
        # go to sign
        sendline(s, "3")
        time.sleep(0.05)
        _ = recv_all(s, timeout=0.2)
        # send enc_msg in this format
        if name == "raw":
            # raw bytes only works with pwntools remote
            if USE_PWN:
                # send raw, followed by newline
                s.send(enc + b'\n')
            else:
                # cannot send raw via socket easily, skip
                sendline(s, enc.hex())
        else:
            sendline(s, enc_repr)
        time.sleep(0.35)
        sign_out = recv_all(s, timeout=0.6).decode(errors='ignore')
        print("=== sign try enc_format:", name, "===\n", sign_out)
        # attempt to extract signature (hex or base64)
        sig = None
        # find long hex (>=128 hex chars)
        m = re.search(r'([0-9a-fA-F]{128,})', sign_out)
        if m:
            hexs = m.group(1).strip()
            # take first 128 chars (64 bytes) as plausible sig
            sig = bytes.fromhex(hexs[:128])
            sig_format = "hex"
        else:
            m2 = re.search(r'([A-Za-z0-9+/=]{40,})', sign_out)
            if m2:
                try:
                    sig = base64.b64decode(m2.group(1))
                    sig_format = "b64"
                except Exception:
                    sig = None
            else:
                # maybe server echoes decimal int signature
                m3 = re.search(r'(\d{100,})', sign_out)
                if m3:
                    decs = m3.group(1).strip()
                    try:
                        sig = int(decs)
                        # convert int to bytes best-effort
                        sig = sig.to_bytes((sig.bit_length()+7)//8, byteorder='big')
                        sig_format = "dec"
                    except Exception:
                        sig = None
        # if we didn't get a signature, still record output and continue
        if sig is None:
            results.append((name, sign_out, None))
            try:
                sendline(s, "5")
            except:
                pass
            try:
                s.close()
            except:
                pass
            continue

        # now try get_flag with multiple signature encodings
        enc_candidates = []
        if name == "raw":
            if USE_PWN:
                enc_candidates.append(("raw", enc))
            enc_candidates.append(("hex", enc.hex()))
            enc_candidates.append(("b64", base64.b64encode(enc).decode()))
            enc_candidates.append(("dec", bytes_to_decimal_str(enc)))
        else:
            # original repr as text
            enc_candidates.append((name, enc_repr))
            enc_candidates.append(("hex", enc.hex()))
            enc_candidates.append(("b64", base64.b64encode(enc).decode()))
            enc_candidates.append(("dec", bytes_to_decimal_str(enc)))

        # try signature encodings to send to get_flag
        sig_texts = []
        sig_texts.append(("hex", sig.hex()))
        sig_texts.append(("b64", base64.b64encode(sig).decode()))
        # decimal form of signature
        try:
            s_int = int.from_bytes(sig, byteorder='big')
            sig_texts.append(("dec", str(s_int)))
        except Exception:
            pass

        # for each enc representation try get_flag
        for enc_name, enc_value in enc_candidates:
            for sig_name, sig_value in sig_texts:
                # we must reopen connection because menu session likely expects fresh
                s2 = connect()
                time.sleep(0.05)
                _ = recv_all(s2, timeout=0.2)
                sendline(s2, "4")
                time.sleep(0.05)
                _ = recv_all(s2, timeout=0.1)
                # send enc_value
                if enc_name == "raw" and USE_PWN:
                    s2.send(enc + b'\n')
                else:
                    sendline(s2, enc_value)
                time.sleep(0.06)
                # send signature
                sendline(s2, sig_value)
                time.sleep(0.4)
                out_flag = recv_all(s2, timeout=1).decode(errors='ignore')
                print(f"--- get_flag try enc={enc_name} sig={sig_name} ->\n{out_flag}")
                results.append((name, sign_out, (enc_name, sig_name, out_flag)))
                try:
                    sendline(s2, "5")
                except:
                    pass
                try:
                    s2.close()
                except:
                    pass

        try:
            sendline(s, "5")
        except:
            pass
        try:
            s.close()
        except:
            pass

    return results

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: exploit_try_formats.py <flagkeeper_key_hex>")
        sys.exit(1)
    fk = sys.argv[1].strip()
    print("Using FK key:", fk)
    res = try_formats_for_sign_and_flag(fk)
    print("DONE. Check outputs above for any flag or clues.")
