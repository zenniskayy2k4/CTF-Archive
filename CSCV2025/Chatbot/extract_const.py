import marshal

pyc_file_path = 'chatbot_extracted/main.pyc'

with open(pyc_file_path, 'rb') as f:
    f.seek(16)  # Bỏ qua 16 byte header của .pyc
    code_obj = marshal.load(f)

    # In ra tất cả các hằng số được lưu trong file bytecode
    print("--- Constants found in bytecode ---")
    for const in code_obj.co_consts:
        print(repr(const))
        print("-" * 20)