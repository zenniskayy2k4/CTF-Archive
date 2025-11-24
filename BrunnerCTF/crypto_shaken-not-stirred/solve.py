cipher = b"wg`{{pgna}&J{!x&2fJWg`{{&g;;;_!x&fJWg`{{&gh"

for shaker in range(256):
    plain = bytes([c ^ shaker for c in cipher])
    if b"brunner{" in plain:
        print(f"shaker = {shaker}")
        print(plain.decode())
        break