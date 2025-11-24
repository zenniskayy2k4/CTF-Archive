ct = bytes.fromhex("0e0b213f26041e480b26217f27342e175d0e070a3c5b103e2526217f27342e175d0e077e263451150104")

# suy khóa từ tiền tố đã biết
key_guess = bytes([c ^ p for c, p in zip(ct, b"crypto{")])  # b"myXORke"
key = b"myXORkey"

pt = bytes([c ^ key[i % len(key)] for i, c in enumerate(ct)])
print(pt.decode())