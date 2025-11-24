import json

def decode_hex_response(hex_string):
    """
    Chuyển đổi một chuỗi hex có dấu hai chấm (:) thành chuỗi ASCII.
    Trả về None nếu có lỗi.
    """
    # Loại bỏ dấu hai chấm khỏi chuỗi hex
    clean_hex = hex_string.replace(":", "")
    try:
        # Chuyển đổi chuỗi hex thành bytes
        byte_data = bytes.fromhex(clean_hex)
        # Giải mã bytes thành chuỗi ASCII
        decoded_string = byte_data.decode('ascii')
        return decoded_string
    except (ValueError, UnicodeDecodeError):
        # Bỏ qua nếu chuỗi không phải là hex hợp lệ hoặc không thể giải mã ASCII
        # (ví dụ: đây là dữ liệu nhị phân thực sự, không phải văn bản)
        return None

def analyze_logs(file_path):
    """
    Đọc tệp log.json, tìm và giải mã tất cả các phản hồi HTTP.
    """
    try:
        with open(file_path, 'r') as f:
            logs = json.load(f)
    except FileNotFoundError:
        print(f"Lỗi: Không tìm thấy tệp '{file_path}'")
        return
    except json.JSONDecodeError:
        print(f"Lỗi: Tệp '{file_path}' không phải là định dạng JSON hợp lệ.")
        return

    print("--- Bắt đầu phân tích log ---")
    
    found_responses = 0
    for i, entry in enumerate(logs):
        # Kiểm tra xem bản ghi có phải là một gói tin HTTP và có trường 'response' không
        if 'http' in entry and 'response' in entry['http']:
            address = entry['http']['address']
            hex_response = entry['http']['response']
            
            # Giải mã chuỗi hex
            decoded_text = decode_hex_response(hex_response)
            
            # Chỉ in ra những phản hồi đã được giải mã thành công thành văn bản
            if decoded_text:
                found_responses += 1
                print(f"\n[+] Phản hồi tìm thấy từ: {address} (Bản ghi #{i+1})")
                # In một phần của chuỗi hex để tham khảo
                print(f"    Hex (một phần): {hex_response[:60]}...")
                print(f"    Giải mã: {decoded_text}")

    if found_responses == 0:
        print("\nKhông tìm thấy phản hồi HTTP nào có thể giải mã thành văn bản.")
    
    print("\n--- Phân tích hoàn tất ---")

# Chạy phân tích trên tệp log.json
if __name__ == "__main__":
    analyze_logs('log.json')