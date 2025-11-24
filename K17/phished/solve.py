import base64
import re

def recover_file_robust(query_file_path, output_filename):
    """
    Đọc file truy vấn, lọc ra chỉ các ký tự Base64 hợp lệ, ghép nối,
    giải mã và lưu lại.
    """
    print(f"--- Bắt đầu xử lý tệp: {query_file_path} ---")
    
    full_base64_string = ""
    
    try:
        with open(query_file_path, 'r') as f:
            lines = f.readlines()
    
        print(f"Đã tìm thấy {len(lines)} dòng truy vấn.")

        for line in lines:
            # Loại bỏ tất cả các ký tự không phải là Base64 (A-Z, a-z, 0-9, +, /)
            # Đây là bước quan trọng nhất để loại bỏ các dấu phân cách rác như '-', '.', '/'
            cleaned_chunk = re.sub(r'[^A-Za-z0-9+/]', '', line)
            full_base64_string += cleaned_chunk

        # Loại bỏ tên tệp có thể bị dính vào cuối sau khi dọn dẹp
        full_base64_string = full_base64_string.replace("transactionstlsx", "").replace("flagdocx", "")

        print(f"Tổng chiều dài chuỗi Base64 đã dọn dẹp: {len(full_base64_string)}")

        # Sửa lỗi padding của Base64
        missing_padding = len(full_base64_string) % 4
        if missing_padding:
            full_base64_string += '=' * (4 - missing_padding)
            print(f"Đã thêm {4 - missing_padding} ký tự padding '='.")

        # Giải mã chuỗi Base64
        decoded_data = base64.b64decode(full_base64_string)
        
        # Ghi dữ liệu đã giải mã ra file
        with open(output_filename, 'wb') as out_file:
            out_file.write(decoded_data)
            
        print(f"✅ Đã khôi phục thành công tệp: {output_filename}\n")

    except Exception as e:
        print(f"❌ Lỗi khi xử lý {query_file_path}: {e}\n")

# --- Chạy quá trình khôi phục ---
# Đảm bảo bạn đã có file transactions_queries.txt và flag_queries.txt từ lệnh tshark
recover_file_robust('transactions_queries.txt', 'recovered_transactions.xlsx')
recover_file_robust('flag_queries.txt', 'recovered_flag.docx')