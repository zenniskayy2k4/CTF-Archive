# solve.py

import sys

def split_vals(s: str):
    """
    Tách một chuỗi số được ghép lại thành hai giá trị ASCII hợp lệ.
    Hàm này ưu tiên việc tách thành các số có 3 chữ số (vì tương ứng với các chữ cái).
    Ví dụ: "114115" -> (114, 115)
           "9548"   -> (95, 48)
    """
    n = len(s)
    possible_splits = []
    # Thử tất cả các cách kết hợp độ dài 2 và 3 chữ số
    for v1_len in [3, 2]: # Ưu tiên tách số có 3 chữ số trước
        if n > v1_len:
            v2_len = n - v1_len
            if v2_len in [2, 3]:
                v1 = int(s[:v1_len])
                v2 = int(s[v1_len:])
                # Kiểm tra xem các giá trị có nằm trong khoảng ASCII in được không
                if 32 <= v1 <= 126 and 32 <= v2 <= 126:
                    possible_splits.append((v1, v2))

    if possible_splits:
        # Trả về kết quả hợp lệ đầu tiên tìm thấy
        return possible_splits[0]
    return None

def parse_line(s: str):
    """
    Phân tích một dòng từ output.txt và trả về hai giá trị cùng chỉ số đã tạo ra nó.
    Trả về tuple dạng: (value_1, value_2, index)
    """
    n = len(s)

    # 1. Thử phân tích theo logic của hàm 'even' (có cấu trúc đối xứng)
    # Chỉ số 'i' có thể dài 1 hoặc 2 chữ số.
    for i_len in [1, 2]:
        if (n - i_len) > 0 and (n - i_len) % 2 == 0:
            prefix_len = (n - i_len) // 2
            i_start = prefix_len

            prefix = s[:i_start]
            idx_str = s[i_start : i_start + i_len]
            suffix = s[i_start + i_len :]

            if prefix == suffix[::-1]: # Kiểm tra tính đối xứng
                vals = split_vals(prefix)
                if vals:
                    # Phân tích thành công theo logic 'even'
                    return (vals[0], vals[1], int(idx_str))

    # 2. Nếu không phải 'even', nó phải là từ hàm 'odd'
    # s = str(val1) + str(val3) + str(i)
    for i_len in [1, 2]:
        if n > i_len:
            idx_str = s[-i_len:]
            vals_str = s[:-i_len]
            vals = split_vals(vals_str)
            if vals:
                # Phân tích thành công theo logic 'odd'
                return (vals[0], vals[1], int(idx_str))

    return None # Không thể xảy ra nếu file input đúng định dạng

def solve():
    """
    Hàm chính để đọc file, đảo ngược logic và tìm flag.
    """
    try:
        with open('output.txt', 'r') as f:
            lines = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print("Lỗi: Không tìm thấy file 'output.txt'.", file=sys.stderr)
        print("Hãy chắc chắn rằng file output.txt nằm cùng thư mục với script này.", file=sys.stderr)
        return

    if len(lines) % 2 != 0:
        print("Lỗi: File output phải có số dòng chẵn.", file=sys.stderr)
        return

    recovered_tuples = []
    # Xử lý các dòng theo từng cặp
    for i in range(0, len(lines), 2):
        line1 = lines[i]
        line2 = lines[i+1]

        parsed1 = parse_line(line1)
        parsed2 = parse_line(line2)

        if not parsed1 or not parsed2:
            print(f"Lỗi khi phân tích dòng {i+1} và {i+2}:", line1, line2, file=sys.stderr)
            return

        # parsed1 có dạng (v_a, v_b, i_a)
        # parsed2 có dạng (v_c, v_d, i_b)
        v_a, v_b, i_a = parsed1
        v_c, v_d, i_b = parsed2

        # Dựa theo logic của mã C++, tái tạo lại 2 tuple ban đầu
        # T1 = (val1, val2, i1)
        # T2 = (val3, val4, i2)
        # line1 được tạo từ (val1, val3, i1)
        # line2 được tạo từ (val2, val4, i2)
        val1, val3, i1 = v_a, v_b, i_a
        val2, val4, i2 = v_c, v_d, i_b

        tuple1 = (val1, val2, i1)
        tuple2 = (val3, val4, i2)

        recovered_tuples.append(tuple1)
        recovered_tuples.append(tuple2)

    # Độ dài của flag = số tuple khôi phục được * 2
    flag_len = len(recovered_tuples) * 2
    flag_chars = [''] * flag_len

    # Điền các ký tự vào đúng vị trí của chúng
    for v1, v2, idx in recovered_tuples:
        # idx là chỉ số của cặp ký tự
        flag_chars[idx * 2] = chr(v1)
        flag_chars[idx * 2 + 1] = chr(v2)

    flag = "".join(flag_chars)
    print("Đã đảo ngược thành công chương trình.")
    print("Flag tìm được là:", flag)

if __name__ == "__main__":
    solve()