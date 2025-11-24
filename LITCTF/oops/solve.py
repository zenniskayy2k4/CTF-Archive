inpstr_1 = "XthEeBeQm3MTsw1ytAHvFNNnL9rhYHBJzrRqmCl2iEhSTzkrhgUAWEYTkqcK1XirEIkiiwVkRc6alzBXJ7ynM69iEoaF5juikG21mBYlbOFOkRAeTS76LfbDcr9cRyWfTdoZk9VKqXmOCtDF2ZpmZmKDFYTnJXTHByHqMLuKEn1V4mdnJ8DvzcLCSFv3LJzBf9Omxs8Egd5lpIDGT65vyyHcgMGobZmnfjaodqyBSd4Fw63IIb1r5KtD2OskgN3NZdymlPU5LtvFTY34r9lYTvePuKFpJEGDTga"
output_1 = 57747851786171493771708682658289659416964365220270

inpstr_2 = "2hnX15jtajgnJYKGAhC5OV1GjQlelUHHgTDJNAogJ2ZwmBO7rj8iMUCYcpqE2ygp7ZzJtVo8wmBQAqISrgZCuLIQSzjvdPytLjLie0esepxDalXD1lekVLvg5IVHsQiC7TcsaiY1SbYu8RvzNVGcA2ljr7lOopMaX855vgeHNoyOVhdJy6FguYYl9qzI4R2XIYO4m3JjcDNRULQOLD4nhtQLRJ7tcGRxMDQDYpUbttr1JuHcrJtvHgVFtK13iFYaS3XFR55QEw52dZDEZ4pRsat74rc8lndWkeoCt8qeBjEprnDjLYW3CVpa21ux1YfdO1sDTNPuQ3mOCE6B6a4kQc7UyM5lmxudjmCDhfD07I4Ls22LbVK7AdZpTWI8ZO90jG1TilcQIMX7Kr3og4Z8pidMDjCl1XOFEjCAySnp36zCa9ohTlRdrUQPcXs0yo7mM25R8rqKAb1DQrx75W7d8Cw8nwcJOr3kvLNG9RX91Gt9eUBEPbqaK9SjJpy8lvhpgMoH3nKy5MnY5KYVO2mH9tHcpnr9YweUsWLz7L1iOPp5v7RYrUzMPn4e2NtMyPEDiMCgzjubgcLQUrl6HytlcWDILZ55zPZUMEoRt4f0QKGy4Z0fuJTcYLxn5HWVg9ZyACMVTCdagMUPpvdKmCteJiL7YcGjkkk1fRWm9pJOFHerwz4DjZ7fUO"
output_2 = 94463895675179066127876381387266781722096911347573

MODULUS = 100000000000000000000000000000000000000000000000151

# Chuyển đổi chuỗi sang số nguyên
S1 = int.from_bytes(inpstr_1.encode(), 'big')
S2 = int.from_bytes(inpstr_2.encode(), 'big')

# Lấy độ dài byte
len1 = len(inpstr_1.encode())
len2 = len(inpstr_2.encode())

# Giải phương trình đồng dư: P * A ≡ B (mod M)
# A = (O1 * 256**len2 - O2 * 256**len1)
# B = (O2 * S1 - O1 * S2)

# Tính A
term_A1 = (output_1 * pow(256, len2, MODULUS)) % MODULUS
term_A2 = (output_2 * pow(256, len1, MODULUS)) % MODULUS
A = (term_A1 - term_A2 + MODULUS) % MODULUS

# Tính B
term_B1 = (output_2 * S1) % MODULUS
term_B2 = (output_1 * S2) % MODULUS
B = (term_B1 - term_B2 + MODULUS) % MODULUS

# Tìm P = B * A^(-1) mod M
# A^(-1) là nghịch đảo modular của A
inv_A = pow(A, -1, MODULUS)
P = (B * inv_A) % MODULUS

# Chuyển số nguyên P trở lại thành chuỗi (flag)
flag_bytes = P.to_bytes((P.bit_length() + 7) // 8, 'big')
flag = flag_bytes.decode()

print(f"The flag is: {flag}")