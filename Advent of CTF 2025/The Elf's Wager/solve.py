target_data_hex = "21312639732C36721D362A711D2F76732C2430762F713F"
target_data = bytes.fromhex(target_data_hex)
xor_key = 0x42  # Key (0x42)

flag = ""
for byte in target_data:
    flag_byte = byte ^ xor_key
    flag += chr(flag_byte)

print(flag)