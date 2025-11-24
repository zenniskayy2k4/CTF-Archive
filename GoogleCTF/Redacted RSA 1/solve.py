import sys, base64
from Crypto.Util.number import bytes_to_long, long_to_bytes, inverse, isPrime
from math import gcd

def read_visible_base64(pem_path):
    with open(pem_path,'r') as f:
        lines=[l.strip() for l in f]
    body=[]
    in_body=False
    for l in lines:
        if l.startswith('-----BEGIN'): in_body=True; continue
        if l.startswith('-----END'): break
        if not in_body: continue
        if '*' in l: continue
        if l=='': continue
        body.append(l)
    s=''.join(body)
    pad=(-len(s))%4
    if pad: s += '='*pad
    return s

def safe_b64decode(s):
    return base64.b64decode(s, validate=False)

def scan_asn1_ints(data):
    ints=[]
    i=0; n=len(data)
    while i<n:
        if data[i]==0x02:
            if i+1>=n: break
            L=data[i+1]; off=i+2; length=0
            if L & 0x80:
                nb=L&0x7f
                if off+nb>n: break
                length=0
                for j in range(nb):
                    length=(length<<8)|data[off+j]
                off += nb
            else:
                length=L
            if off+length>n:
                avail = max(0, n-off)
                val_bytes = data[off:off+avail]
                val = bytes_to_long(val_bytes) if avail>0 else 0
                ints.append((i,length,avail,val,val_bytes))
                break
            else:
                val_bytes=data[off:off+length]; val=bytes_to_long(val_bytes)
                ints.append((i,length,length,val,val_bytes))
                i = off + length
                continue
        i += 1
    return ints

def brute_p_from_dp(e, dp, max_k=1<<20):
    num = e*dp - 1
    found=[]
    for k in range(1, max_k):
        if num % k != 0: continue
        p = num//k + 1
        if p>2 and isPrime(p):
            found.append((k,p))
            if len(found)>=10: break
    return found

def rebuild_and_write(p,q,e=65537,out='recovered.pem'):
    n=p*q; phi=(p-1)*(q-1); d=inverse(e,phi)
    from Crypto.PublicKey import RSA
    key = RSA.construct((n,e,d,p,q))
    pem = key.export_key('PEM')
    open(out,'wb').write(pem)
    return out

def main():
    if len(sys.argv)<2:
        print("Usage: python3 recover_from_masked_pem.py key.pem"); return
    pem=sys.argv[1]
    vis = read_visible_base64(pem)
    data = safe_b64decode(vis)
    ints = scan_asn1_ints(data)
    print("[*] Found %d INTEGER-like entries" % len(ints))
    for idx,(pos,decl,avail,val,valb) in enumerate(ints):
        print(f"#{idx}: pos={pos} decl={decl} avail={avail} bits={val.bit_length()} hex_pref={valb[:8].hex()}...")
    # Heuristic: pick candidates with bit length ~ half modulus as q/dp
    # Try each candidate as dp:
    for idx,(pos,decl,avail,val,valb) in enumerate(ints):
        if val.bit_length() < 200: continue
        print(f"\n[*] Trying candidate #{idx} as dp (bits={val.bit_length()})")
        sols = brute_p_from_dp(65537, val, max_k=1<<19)
        if sols:
            for k,p in sols:
                print(f" -> kp={k} p_bits={p.bit_length()} p_hex_pref={hex(p)[:80]}")
    print("\nDone. If you find plausible p or q, use rebuild_and_write(p,q) to get PEM.")

if __name__=='__main__':
    main()
