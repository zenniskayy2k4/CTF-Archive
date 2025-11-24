from string import printable

def flip(b, pos):
    bits = list(b)
    bits[pos] = '0' if bits[pos] == '1' else '1'
    return ''.join(bits)

def flip2(b, pos1, pos2):
    bits = list(b)
    bits[pos1] = '0' if bits[pos1] == '1' else '1'
    bits[pos2] = '0' if bits[pos2] == '1' else '1'
    return ''.join(bits)

def b2c(b):
    try:
        return chr(int(b, 2))
    except:
        return '?'
    
def append(l, v):
    if v[2] in printable:
        l.append(v)

def generate_flips(blk):
    results = []
    n = len(blk)
    for i in range(n):
        orig = blk[i]
        append(results, (i, orig, b2c(orig), "original"))
        for b in range(8):
            flp = flip(orig, b)
            append(results, (i, flp, b2c(flp), f"flip bit {b}"))
        for b1 in range(8):
            for b2 in range(b1 + 1, 8):
                flp2 = flip2(orig, b1, b2)
                append(results, (i, flp2, b2c(flp2), f"flip bits {b1},{b2}"))
    return results

blk = [
"11001001", "01110010", "01110100", "01100110", "01111011", "01100111",
"01100101", "01110100", "01011111", "01100010", "01100001", "01101001",
"01110100", "01100101", "01100100", "11011111", "01101011", "01110100",
"01110011", "01010111", "01111001", "01100011", "01110100", "01110100",
"10100001", "01101100", "01101100", "01111001", "01011111", "01100001",
"01101110", "01011111", "01100001", "01101110", "01101111", "01110011",
"00010001", "10111101", "11001101", "10000101", "11010010", "01110101",
"01110010", "01110101", "01110010", "01110011", "01111101"
]

flips = generate_flips(blk)
for i, bin_str, char, desc in flips:
    print(f"Block {i} ({desc}): {bin_str} -> {char}")
    
#ictf{get_baited_its_actually_an_ano}