#!/usr/bin/env python3
# solve.py (fixed padding-oracle exploit with retries & stronger confirmation)
from pwn import remote
import hashlib, time, re, sys, os, random

HOST = "52.59.124.14"
PORT = 5102
BLOCK = 16
PROMPT = b"input cipher (hex): "

# ---------- network helpers ----------
def make_conn():
    io = remote(HOST, PORT, timeout=10)
    io.recvuntil(PROMPT)
    return io

def send_cipher_and_get_resp(io, data_bytes, allow_reconnect=True):
    """Send cipher (bytes) as hex. Return (resp_text, io). Reconnect once on failure."""
    hexstr = data_bytes.hex().encode()
    try:
        io.sendline(hexstr)
        out = io.recvuntil(PROMPT, timeout=10)
        return out.decode(errors='ignore'), io
    except Exception:
        try:
            io.close()
        except Exception:
            pass
        if allow_reconnect:
            io = make_conn()
            io.sendline(hexstr)
            out = io.recvuntil(PROMPT, timeout=10)
            return out.decode(errors='ignore'), io
        raise

def padding_ok_from_response(resp_text):
    return "invalid padding" not in resp_text.lower()

# ---------- crypto helpers ----------
def pkcs7_pad(msg, block=16):
    padlen = block - (len(msg) % block)
    return msg + bytes([padlen]) * padlen

# ---------- oracle attack ----------
def recover_intermediate_for_block(io, C, max_retries_per_block=5, verbose=False):
    """
    Recover intermediate AES_decrypt(C) (16 bytes) using padding oracle.
    Strategy:
      - Try with initial C_prev = zeros.
      - If fail to find a confirmed byte at some pos, retry whole block with a random C_prev (up to retries).
      - For each candidate, perform two confirmations:
          1) flip another byte and check padding becomes invalid;
          2) (if ambiguous) reconnect and re-test candidate on fresh connection.
    Returns (I_bytes, io)
    """
    assert len(C) == BLOCK
    for attempt_block in range(max_retries_per_block):
        # choose initial C_prev: zeros for first attempt, random for next attempts
        if attempt_block == 0:
            C_prev = bytearray([0]*BLOCK)
        else:
            C_prev = bytearray(os.urandom(BLOCK))
        mod = bytearray(C_prev)
        I = [0]*BLOCK
        if verbose:
            print(f"[block attempt {attempt_block+1}/{max_retries_per_block}] using C_prev = {C_prev.hex()[:30]}...")

        try:
            # for each byte from last to first
            for pos in range(BLOCK-1, -1, -1):
                pad = BLOCK - pos
                # set suffix bytes to produce pad
                for j in range(BLOCK-1, pos, -1):
                    mod[j] = (C_prev[j] ^ I[j] ^ pad) & 0xff

                found = False
                candidates = []
                # try all possible guesses
                for guess in range(256):
                    mod[pos] = guess
                    test = bytes(mod) + bytes(C)
                    resp, io = send_cipher_and_get_resp(io, test)
                    ok = padding_ok_from_response(resp)
                    if ok:
                        candidates.append(guess)
                        # if many candidates, continue scanning to collect them
                if not candidates:
                    # no candidate for this pos on this C_prev -> trigger outer retry (random C_prev)
                    raise ValueError(f"No candidates at pos {pos} with this C_prev, will retry block with new C_prev")

                # prefer unique candidate; otherwise try to confirm among candidates
                selected = None
                if len(candidates) == 1:
                    selected = candidates[0]
                    # do a quick confirmation by flipping another byte
                    flip_idx = pos-1 if pos-1 >= 0 else pos
                    mod_confirm = bytearray(mod)
                    mod_confirm[flip_idx] ^= 1
                    resp2, io = send_cipher_and_get_resp(io, bytes(mod_confirm)+bytes(C))
                    ok2 = padding_ok_from_response(resp2)
                    if ok2:
                        # flip didn't break padding -> ambiguous; force further confirmation below
                        pass
                    else:
                        # confirmed
                        selected = candidates[0]

                if selected is None:
                    # multiple candidates or unconfirmed unique: attempt stronger confirmation
                    # Try each candidate but test on a fresh connection to avoid server state dependency
                    confirmed_found = False
                    for cand in candidates:
                        mod[pos] = cand
                        # quick flip check first
                        flip_idx = pos-1 if pos-1 >= 0 else pos
                        mod_confirm = bytearray(mod)
                        mod_confirm[flip_idx] ^= 1
                        resp2, io = send_cipher_and_get_resp(io, bytes(mod_confirm)+bytes(C))
                        ok2 = padding_ok_from_response(resp2)
                        if not ok2:
                            # likely good candidate — now double-check on fresh connection
                            try:
                                io2 = make_conn()
                                test = bytes(mod) + bytes(C)
                                resp3, io2 = send_cipher_and_get_resp(io2, test, allow_reconnect=False)
                                ok3 = padding_ok_from_response(resp3)
                                io2.close()
                            except Exception:
                                ok3 = False
                            if ok3:
                                selected = cand
                                confirmed_found = True
                                break
                            else:
                                # if new connection disagrees, continue searching
                                continue
                        else:
                            # flip didn't invalidate padding => ambiguous candidate; skip
                            continue

                    if not confirmed_found:
                        # none confirmed -> ambiguous situation for this C_prev
                        raise ValueError(f"Ambiguous candidates at pos {pos}: {candidates}; retrying block with new C_prev")

                # compute I[pos] from selected
                Ipos = (selected ^ C_prev[pos] ^ pad) & 0xff
                I[pos] = Ipos
                if verbose:
                    print(f"[byte] pos {pos} -> 0x{Ipos:02x} (selected {selected})")
                # continue to next pos

            # if all bytes recovered, return
            return bytes(I), io

        except ValueError as e:
            if verbose:
                print(f"[retry block] {e}")
            # loop to try new random C_prev
            continue

    # if we reach here, all retries exhausted
    raise Exception("Failed to recover intermediate for block after retries")

def build_cipher_for_plaintext(io, P, verbose=False):
    """
    Build ciphertext whose decryption equals padded plaintext P.
    Returns (cipher_bytes, io)
    """
    assert len(P) % BLOCK == 0
    blocks = [P[i:i+BLOCK] for i in range(0, len(P), BLOCK)]
    k = len(blocks)
    C_blocks = [None]*k
    # pick random last block
    C_blocks[-1] = os.urandom(BLOCK)

    for j in range(k-1, -1, -1):
        if verbose:
            print(f"[build] recovering D for C_{j} ...")
        D_j, io = recover_intermediate_for_block(io, C_blocks[j], verbose=verbose)
        prev = bytes(x ^ y for x, y in zip(D_j, blocks[j]))
        if j == 0:
            IV = prev
            final = IV
            for b in C_blocks:
                final += b
            return final, io
        else:
            C_blocks[j-1] = prev
    raise Exception("unexpected flow")

# ---------- main exploit ----------
def exploit(verbose=False):
    io = make_conn()
    payload = b'{"command":"print(flag)"}'
    payload_padded = pkcs7_pad(payload, BLOCK)
    if verbose:
        print("Payload:", payload)
        print("Padded length:", len(payload_padded))
    print("[*] Starting build (this will do many oracle queries). Be patient.")
    start = time.time()
    cipher, io = build_cipher_for_plaintext(io, payload_padded, verbose=verbose)
    print(f"[*] Build finished in {time.time()-start:.1f}s, sending final ciphertext")
    resp, io = send_cipher_and_get_resp(io, cipher)
    print("=== server response ===")
    print(resp)
    try:
        io.interactive()
    except Exception:
        io.close()

if __name__ == "__main__":
    exploit(verbose=True)
