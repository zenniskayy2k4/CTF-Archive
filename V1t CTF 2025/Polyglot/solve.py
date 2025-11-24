import zlib
import sys
import os

if len(sys.argv) != 2:
    print(f"Sử dụng: python {sys.argv[0]} <thư mục chứa file zlib>")
    sys.exit(1)

target_dir = sys.argv[1]

for filename in os.listdir(target_dir):
    if filename.endswith(".zlib"):
        input_path = os.path.join(target_dir, filename)
        output_path = os.path.join(target_dir, filename.replace('.zlib', '.decompressed'))
        
        try:
            with open(input_path, 'rb') as f_in:
                compressed_data = f_in.read()
            
            decompressed_data = zlib.decompress(compressed_data)
            
            with open(output_path, 'wb') as f_out:
                f_out.write(decompressed_data)
            
            print(f"Đã giải nén thành công: {input_path} -> {output_path}")
        except Exception as e:
            print(f"Lỗi khi giải nén {input_path}: {e}")