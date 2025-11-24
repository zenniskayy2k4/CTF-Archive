# Lưu ý là chạy 2 lần

def create_reverse_table():
    try:
        with open('emoji.txt', 'r', encoding='utf-8') as f:
            emojis = list(f.read().strip())
        reverse_table = {ch: i for i, ch in enumerate(emojis)}
        return reverse_table
    except FileNotFoundError:
        print("Lỗi: Không tìm thấy file 'emoji.txt'.")
        print("Vui lòng đảm bảo file 'emoji.txt' nằm cùng thư mục với script này.")
        return None

def decode(encoded_data, reverse_table):
    # 1. Loại bỏ ký tự đệm '🚀' ở cuối chuỗi
    encoded_data = encoded_data.strip().rstrip('🚀')

    # 2. Chuyển đổi mỗi emoji thành chỉ số (số nguyên) tương ứng
    try:
        indices = [reverse_table[char] for char in encoded_data]
    except KeyError as e:
        return f"Lỗi: Emoji không hợp lệ trong chuỗi đầu vào: {e}"

    # 3. Chuyển mỗi chỉ số thành chuỗi nhị phân 10-bit và nối chúng lại
    bits = ''.join(f'{i:010b}' for i in indices)

    # 4. Loại bỏ các bit đệm. Độ dài chuỗi bit gốc phải là bội số của 8.
    # Ta lấy độ dài là bội số của 8 lớn nhất mà không vượt quá độ dài hiện tại.
    valid_bit_length = (len(bits) // 8) * 8
    bits = bits[:valid_bit_length]

    # 5. Chia chuỗi bit thành các nhóm 8-bit
    byte_chunks = [bits[i:i+8] for i in range(0, len(bits), 8)]

    # 6. Chuyển các nhóm nhị phân thành byte
    decoded_bytes = bytes([int(chunk, 2) for chunk in byte_chunks])

    # 7. Giải mã chuỗi byte thành văn bản (sử dụng utf-8)
    try:
        decoded_string = decoded_bytes.decode('utf-8')
        return decoded_string
    except UnicodeDecodeError:
        return "Lỗi: Không thể giải mã thành văn bản UTF-8. Kết quả có thể là dữ liệu nhị phân."

if __name__ == '__main__':
    # Tạo bảng tra cứu ngược từ file emoji.txt
    reverse_emoji_table = create_reverse_table()

    if reverse_emoji_table:
        # Yêu cầu người dùng nhập chuỗi cần giải mã
        # encoded_message = "🪛🔱🛜🫗🚞👞🍁🎩🚎🐒🌬🧨🖱🥚🫁🧶🪛🔱👀🔧🚞👛😄🎩🚊🌡🌬🧮🤮🥚🫐🛞🪛🔱👽🔧🚞🐻🔳🎩😥🪨🌬🩰🖖🥚🫐🪐🪛🔱👿🫗🚞🏵📚🎩🚊🎄🌬🧯🕺🥚🫁📑🪛🔰🐀🫗🚞💿🔳🎩🚲🚟🌬🧲🚯🥚🫁🚰🪛🔱💀🔧🚞🏓🛼🎩🚿🪻🌬🧪🙊🥚🫐🧢🪛🔱🛟🔧🚞🚋🫳🎩😆🏉🌬🧶🚓🥚🫅💛🪛🔱🔌🐃🚞🐋🥍🎩😱🤮🌬🩰🛳🥚🫀📍🪛🔰🐽🫗🚞💿🍁🎩🚊🌋🌬🧵🔷🚀🚀🚀"
        encoded_message = "🪛🔰🛏🍈📛🤵🔈🚁📷🦨🥩💇💼🥇🧷🥳🎆🚇🔅👶📷🚇🤧🗣💐🥵🌚🦽🏖🧇🪥🦿🏋🛜🙆🧀🏋🔭🥬🍲🔫🚀🚀🚀"
        # Giải mã thông điệp
        decoded_message = decode(encoded_message, reverse_emoji_table)
        
        # In kết quả
        print("\n--------------------")
        print("Kết quả giải mã:")
        print(decoded_message)
        print("--------------------")