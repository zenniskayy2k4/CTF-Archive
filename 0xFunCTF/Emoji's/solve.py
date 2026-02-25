import urllib.parse

def decode_ctf_tags(text):
    # Giải mã URL encoding nếu cần
    if "%" in text:
        text = urllib.parse.unquote(text)
        
    decoded = ""
    for char in text:
        cp = ord(char)
        # Các ký tự ẩn của bài này nằm ở dải E0100
        if 0xE0100 <= cp <= 0xE017F:
            # Công thức: Lấy phần lẻ (cp - E0100) rồi cộng Shift 16
            ascii_val = (cp - 0xE0100) + 16
            decoded += chr(ascii_val)
    return decoded

# Test với nội dung bạn cung cấp
cipher_text = "Emo󠄠󠅨󠅖󠅥󠅞󠅫󠄣󠅝󠅟󠅚󠅙󠅏󠅣󠄣󠅓󠅢󠄣󠅤󠅏󠅕󠅝󠅒󠄣󠅔󠅏󠄡󠅞󠅏󠅤󠄡󠅤󠅜󠅕󠅭ji's"
hint_text = "something seems to be in here 🤔󠅞󠅟󠅤󠅘󠅙󠅞󠅗󠄐󠅤󠅟󠄐󠅒󠅕󠄐󠅕󠅨󠅠󠅕󠅓󠅤󠅕󠅔󠄐󠅘󠅕󠅢󠅕󠄞?"

print(f"Flag tìm thấy trong tiêu đề: {decode_ctf_tags(cipher_text)}")
print(f"Hint ẩn trong câu hỏi: {decode_ctf_tags(hint_text)}")