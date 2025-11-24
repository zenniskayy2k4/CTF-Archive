import dis
import marshal
import sys

# Đôi khi cần tăng giới hạn đệ quy để dis có thể xử lý các file phức tạp
sys.setrecursionlimit(5000) 

# Đường dẫn đến file .pyc cần phân tích
pyc_file_path = 'chatbot_extracted/main.pyc'

try:
    with open(pyc_file_path, 'rb') as f:
        # 16 byte đầu là header của file .pyc, chúng ta bỏ qua
        f.seek(16)
        
        # marshal.load() sẽ đọc đối tượng code từ file
        code_obj = marshal.load(f)
        
        # dis.dis() sẽ phân tách và in ra bytecode
        print(f"--- Bytecode for {pyc_file_path} ---")
        dis.dis(code_obj)

except Exception as e:
    print(f"An error occurred: {e}")