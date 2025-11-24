import marshal
import dis
import sys
import io
import os

def disassemble_pyc(pyc_path, output_filename="disassembled_output.asm"):
    """
    Tải Code Object từ file .pyc và phân tích bytecode, sau đó lưu vào file.
    
    :param pyc_path: Đường dẫn đến file .pyc.
    :param output_filename: Tên file sẽ lưu kết quả phân tích.
    """
    # Chiều dài header (Magic Number, Timestamp, v.v.). 16 bytes cho Python 3.11+
    MAGIC_LEN = 16 

    # 1. Tải Code Object
    try:
        with open(pyc_path, "rb") as f:
            # Bỏ qua header
            f.seek(MAGIC_LEN) 
            code_object = marshal.load(f)
    except FileNotFoundError:
        print(f"Lỗi: Không tìm thấy file '{pyc_path}'.")
        return
    except Exception as e:
        print(f"Lỗi khi đọc file '{pyc_path}' (Đảm bảo đúng phiên bản Python): {e}")
        return

    # 2. Phân tích và lưu kết quả vào file
    try:
        # Sử dụng io.StringIO để bắt output của dis.dis()
        output_stream = io.StringIO()
        
        # Chuyển hướng output của dis.dis() vào output_stream
        dis.dis(code_object, file=output_stream)
        
        bytecode_analysis = output_stream.getvalue()
        
        # Ghi kết quả vào file
        with open(output_filename, "w", encoding="utf-8") as outfile:
            outfile.write(f"--- Bytecode Analysis for: {pyc_path} ---\n")
            outfile.write(f"--- Python Runtime Version: {sys.version.split(' ')[0]} ---\n\n")
            outfile.write(bytecode_analysis)
        
        print(f"✅ Phân tích bytecode thành công và đã lưu vào file: **{output_filename}**")

    except Exception as e:
        print(f"Lỗi khi phân tích bytecode: {e}")
        print("Vui lòng đảm bảo bạn đang chạy script này bằng **CHÍNH XÁC phiên bản Python** đã biên dịch file .pyc đó.")


if __name__ == "__main__":
    # Tên file .pyc đầu vào
    input_file = "Malayo.pyc"
    
    # Tên file đầu ra sẽ được tạo
    output_file = os.path.splitext(input_file)[0] + "_disassembly.asm"
    
    disassemble_pyc(input_file, output_file)