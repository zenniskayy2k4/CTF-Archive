# MÃ NÀY DỰA TRÊN VIỆC ĐỌC TRUNG THÀNH NHẤT VỚI DECOMPILER
# NÓ SẼ GÂY RA LỖI VALUEERROR NHƯ BẠN THẤY, CHỨNG TỎ CÓ SỰ KHÁC BIỆT DỮ LIỆU
def solve():
    try:
        with open('rockyou.txt', 'r', encoding='utf-8', errors='ignore') as f:
            wordlist = [line.strip() for line in f]
    except FileNotFoundError:
        print("Lỗi: Không tìm thấy file 'rockyou.txt'.")
        return

    word_to_index = {word: i for i, word in enumerate(wordlist)}

    encoded_text = "charlie junior babygirl soccer qwerty 111111 000000 tigger jessica jasmine joseph 12345 tigger chelsea melissa 123123 mickey computer anthony chelsea brandon brandon matthew soccer bubbles playboy spongebob eminem ashley password ashley"
    encoded_words = encoded_text.strip().split()

    try:
        encoded_indices = [word_to_index[word] for word in encoded_words]
    except KeyError as e:
        print(f"Lỗi: Từ '{e.args[0]}' không có trong rockyou.txt.")
        return

    # Logic dịch ngược theo sát nhất với mã C++
    key = encoded_indices[0]
    print(f"[+] Giả định key từ 'charlie': {key}")
    
    decoded_chars = []
    
    # State ban đầu để giải mã ký tự đầu tiên (i=0) là key
    state = key

    # Vòng lặp giải mã
    for i in range(len(encoded_indices) - 1):
        current_word_index = encoded_indices[i + 1]
        
        # Giải mã ký tự
        char_code = current_word_index ^ state
        
        # Dòng này sẽ gây lỗi, chứng tỏ có vấn đề với dữ liệu đầu vào
        print(f"i={i}: index={current_word_index}, state={state}, char_code={char_code}")
        decoded_chars.append(chr(char_code))

        # Cập nhật state cho vòng lặp tiếp theo
        state = char_code ^ (i % 256)

    flag = "".join(decoded_chars)
    print("\n[+] Flag đã giải mã là:")
    print(flag)

if __name__ == '__main__':
    solve()