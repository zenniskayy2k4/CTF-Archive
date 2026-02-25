import itertools

# bảng mapping theo số tầng đen
con_map = {
    1: 'f', 2: 'g', 3: 'p', 4: 't', 5: 'r'
}

dig_map = {
    1: '0', 2: '1', 3: '4', 4: '5'
}

vow_map = {
    1: 'e', 2: 'o', 3: 'u'
}

# mỗi fragment -> danh sách depth
tree = [
    ('A', [3]),
    ('B', [5, 1]),
    ('A', [1]),
    ('C', [1, 4]),
    ('D', [4]),
    ('E', [2, 5]),

    ('B', [3, 3]),
    ('C', [3, 2]),

    ('E', [1, 2]),
    ('A', [2]),
    ('E', [1, 5]),
    ('A', [4]),
]

# loại có thể theo phân tích ảnh
types = {
    'A': ['c', 'd'],
    # 'B': ['cd', 'vc', 'vd'],
    'B': ['cd'],
    'C': ['cd', 'vc', 'vd'],
    'D': ['c', 'd'],
    # 'E': ['cd', 'vc', 'vd'],
    'E': ['vc'],
}

def decode_fragment(ftype, depths):
    if ftype == 'c':
        return con_map[depths[0]]
    if ftype == 'd':
        return dig_map[depths[0]]
    if ftype == 'cd':
        return con_map[depths[0]] + dig_map[depths[1]]
    if ftype == 'vc':
        return vow_map[depths[0]] + con_map[depths[1]]
    if ftype == 'vd':
        return vow_map[depths[0]] + dig_map[depths[1]]
    return ""

letters = ['A', 'B', 'C', 'D', 'E']

for combo in itertools.product(
    types['A'],
    types['B'],
    types['C'],
    types['D'],
    types['E']
):
    assign = dict(zip(letters, combo))

    try:
        out = ""
        for letter, depths in tree:
            out += decode_fragment(assign[letter], depths)

        # cắt theo cấu trúc flag
        word1 = out[:9]
        word2 = out[9:13]
        word3 = out[13:19]

        flag = f"lactf{{{word1}_{word2}_{word3}}}"

        # lọc flag có chữ cái hợp lý
        if any(c in flag for c in "aeiou"):
            print(flag)

    except:
        pass
