import base64
encoded_string = "c3Vue2MwdjNyMW5nX3VyX0I0NTM1fQ=="
decoded_bytes = base64.b64decode(encoded_string)
print(decoded_bytes.decode('utf-8'))