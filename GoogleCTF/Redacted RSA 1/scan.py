import base64
from solve import read_visible_base64, safe_b64decode, scan_asn1_ints

pem_path = "key.pem"
b64 = read_visible_base64(pem_path)
data = safe_b64decode(b64)

ints = scan_asn1_ints(data)
print(f"[*] Found {len(ints)} INTEGER-like entries")
for idx, (pos, decl, avail, val, valb) in enumerate(ints):
    print(f"#{idx}: pos={pos} decl={decl} avail={avail} bits={val.bit_length()} hex_pref={valb[:8].hex()}...")
    print(f"    value (decimal): {val}")
    print(f"    value (hex): {valb.hex()}")