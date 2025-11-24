import codecs

# Chuỗi hex từ thử thách
hex_string = "d08597898385d96d85a29985a585d96d95819789a99981d46d8588e36da2c96da28988e36d8495c16da285948199c6958981d46d95d66df0f7f9f16d8588e36d95c96d8485a2e46da281e66dc3c9c4c3c2c5c099859595a49982"

# Chuyển chuỗi hex thành một đối tượng bytes
byte_data = bytes.fromhex(hex_string)

# Giải mã đối tượng bytes bằng code page EBCDIC cp037
# Chúng ta phải thử các code page khác nhau, nhưng cp037 là phổ biến nhất.
# Decode byte_data in reverse order because of the "Reverse Recipe" hint
# We need to decode the reversed bytes, not reverse the string after decoding.
decoded_text_reversed_bytes = codecs.decode(byte_data[::-1], 'cp037')


print("Kết quả giải mã:")
print(decoded_text_reversed_bytes)