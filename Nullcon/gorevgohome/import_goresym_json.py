import json
from ghidra.program.model.symbol import SourceType

def run():
    # Mở hộp thoại để người dùng chọn file JSON
    try:
        json_file = askFile("Select GoReSym JSON file", "Go!")
    except Exception as e:
        print("Script cancelled.")
        return

    print("Reading JSON file: " + json_file.absolutePath)
    
    # Đọc và phân tích file JSON
    with open(json_file.absolutePath, 'r') as f:
        data = json.load(f)

    # GoReSym mới xuất ra 'UserFunctions' thay vì 'Functions'->'User'
    if not data or 'UserFunctions' not in data:
        print("Error: JSON file does not contain expected 'UserFunctions' key.")
        return

    functions_to_rename = data['UserFunctions']
    renamed_count = 0

    print("Found {} functions to rename. Starting process...".format(len(functions_to_rename)))

    # Lặp qua từng hàm trong file JSON và đổi tên
    for func_info in functions_to_rename:
        func_addr_int = func_info.get('Start')
        func_name = func_info.get('FullName')

        if func_addr_int is None or func_name is None:
            continue
        
        # GoReSym có thể chứa các ký tự không hợp lệ cho tên hàm Ghidra
        # Chúng ta sẽ thay thế chúng bằng dấu gạch dưới
        safe_func_name = func_name.replace('[', '_').replace(']', '_').replace('.', '_').replace('*', 'ptr_').replace('{', '_').replace('}', '_').replace(' ', '_')


        # Chuyển đổi địa chỉ số nguyên sang đối tượng Address của Ghidra
        func_addr = toAddr(func_addr_int)
        
        # Lấy hàm tại địa chỉ đó
        f = getFunctionAt(func_addr)

        if f is not None:
            try:
                # Đặt tên mới cho hàm
                # SourceType.IMPORTED hoặc USER_DEFINED đều được
                f.setName(safe_func_name, SourceType.IMPORTED)
                renamed_count += 1
            except Exception as e:
                print("Could not rename function at {}: {}".format(func_addr, e))
        else:
            # Nếu chưa có hàm, hãy tạo một hàm mới
            try:
                createFunction(func_addr, safe_func_name)
                renamed_count += 1
                print("Created and named new function at: {}".format(func_addr))
            except Exception as e:
                print("Could not create function at {}: {}".format(func_addr, e))

                
    print("Finished! Renamed/Created {} functions.".format(renamed_count))

# Chạy hàm chính
run()