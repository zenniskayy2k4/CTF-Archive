import zlib
import base64
from itsdangerous import base64_decode

# Lấy phần đầu tiên của cookie (bỏ đi dấu chấm ở đầu)
cookie_data = "eJydjkFuxCAMRa-CWEcVJkDMnGL21Sgyxp5ETSdVSFejuXupeoOurOdv67-nnXWjtkizl_enNWcf9lNao7vYwV43oSZm2-9mfZhzN8TcQ3MuazNf_ebN3l7DP_9uQy8_pC32orQ16bhWe7Hsi08UkLJSdBH9OCpHQp97glOOIY_sARE0eqhJE6PUBGMRAYWcJkFXgBSDz9VLcYHRA2UMk88xukQyulQDRGBGlFhHnahAnvS3uPvP302OPxvoyO3Q-dw_5NEXQVMKNUMAyTWIo5qKY-Ypc-k6XNXFjmpfP2wQaXA.aNj2zw.bpa144-QHRYsbU71CzMEbPMkIg8"

try:
    # Bước 1: Base64 Decode
    # Flask sử dụng URL-safe base64, nên dùng itsdangerous.base64_decode là an toàn nhất
    # Hoặc bạn có thể thêm padding và dùng base64.urlsafe_b64decode
    decoded_data = base64_decode(cookie_data)
    
    # Bước 2: Zlib Decompress
    decompressed_data = zlib.decompress(decoded_data)
    
    print("Decoded Session Data:")
    print(decompressed_data)

except Exception as e:
    print(f"An error occurred: {e}")
    # Nếu có lỗi padding, thử thêm padding thủ công
    try:
        padding = b'=' * (-len(cookie_data) % 4)
        decoded_data_padded = base64.urlsafe_b64decode(cookie_data.encode() + padding)
        decompressed_data = zlib.decompress(decoded_data_padded)
        print("\nDecoded Session Data (with padding):")
        print(decompressed_data)
    except Exception as e2:
        print(f"Failed with padding as well: {e2}")