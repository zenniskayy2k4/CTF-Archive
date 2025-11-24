import sys

# Bảng chữ cái gốc từ file binary
CHARSET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ{}.,: "

def to_signed_byte(b):
    """Chuyển một byte (0-255) thành giá trị có dấu (-128 to 127)."""
    return b if b < 128 else b - 256

class Node:
    def __init__(self, key):
        # Key được lưu dưới dạng giá trị có dấu
        self.key = to_signed_byte(key)
        self.left = None
        self.right = None

def parse_output(data):
    paths = []; current_path = ""
    emojis = [char for char in data if char in "🌴🌲🌳🎄"]
    for char in emojis:
        current_path += char
        if char in "🌳🎄": paths.append(current_path); current_path = ""
    return paths

def solve():
    try:
        with open("output", "r", encoding="utf-8") as f:
            output_data = f.read().strip()
    except FileNotFoundError: print("Lỗi: Không tìm thấy file output."); return

    paths = parse_output(output_data)
    print(f"[*] Đã phân tích được {len(paths)} đường đi của ký tự.")
    print(f"[*] Áp dụng logic cuối cùng: So sánh CÓ DẤU (signed comparison).")

    for xor_key in range(256):
        sys.stdout.write(f"\r[*] Đang thử khóa XOR: {xor_key}...")
        sys.stdout.flush()

        root = None; flag = ""; possible = True
        for path in paths:
            # Ràng buộc bây giờ là cho các giá trị có dấu
            lower_bound, upper_bound = -129, 128 
            current_node, collision_keys = root, set()

            for move in path[:-1]:
                if not current_node: possible = False; break
                collision_keys.add(current_node.key)
                if move == '🌴': upper_bound = min(upper_bound, current_node.key); current_node = current_node.left
                elif move == '🌲': lower_bound = max(lower_bound, current_node.key); current_node = current_node.right
                else: possible = False; break
            if not possible: break
            
            terminator = path[-1]
            possible_chars = []
            
            for char in CHARSET:
                # Tính key dưới dạng byte không dấu trước
                potential_key_unsigned = ord(char) ^ xor_key
                # Chuyển nó thành dạng có dấu để so sánh
                potential_key_signed = to_signed_byte(potential_key_unsigned)

                # Kiểm tra ràng buộc
                if not (lower_bound < potential_key_signed < upper_bound):
                    continue

                is_valid = False
                if terminator == '🌳': # Chèn thành công
                    if potential_key_signed not in collision_keys:
                        is_valid = True
                elif terminator == '🎄': # Xung đột
                    if current_node and potential_key_signed == current_node.key:
                        is_valid = True
                
                if is_valid:
                    possible_chars.append(char)

            if len(possible_chars) == 1:
                found_char = possible_chars[0]
                flag += found_char
                
                # Cập nhật cây ảo
                new_key_unsigned = ord(found_char) ^ xor_key
                # Chỉ thêm node mới nếu chèn thành công
                if path[-1] == '🌳':
                    if root is None: root = Node(new_key_unsigned)
                    else:
                        node = root
                        new_key_signed = to_signed_byte(new_key_unsigned)
                        while True:
                            if new_key_signed < node.key:
                                if node.left is None: node.left = Node(new_key_unsigned); break
                                node = node.left
                            elif new_key_signed > node.key:
                                if node.right is None: node.right = Node(new_key_unsigned); break
                                node = node.right
                            else: break
            else:
                possible = False; break
        
        if possible and len(flag) == len(paths):
            print(f"\n[+] Thành công! Tìm thấy cờ hợp lệ với khóa XOR: {xor_key}")
            print(f"[+] Cờ: {flag}")
            return
            
    print("\n[-] Đã thử hết tất cả các khả năng. Không tìm thấy lời giải.")

if __name__ == "__main__":
    solve()