import pypdf

# Ánh xạ các ký tự Zero-Width sang mã Morse
# Đây là một cách mã hóa phổ biến
ZW_TO_MORSE = {
    '\u200b': '.',  # Zero-Width Space -> DOT
    '\u200c': '-',  # Zero-Width Non-Joiner -> DASH
    '\u200d': ' ',  # Zero-Width Joiner -> SPACE between letters
}

# Ánh xạ mã Morse ngược lại sang ký tự
MORSE_TO_CHAR = {
    '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
    '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
    '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
    '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
    '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
    '--..': 'Z', '-----': '0', '.----': '1', '..---': '2',
    '...--': '3', '....-': '4', '.....': '5', '-....': '6',
    '--...': '7', '---..': '8', '----.': '9', '.-.-.-': '.',
    '--..--': ',', '..--..': '?', '-..-.': '/', '-....-': '-',
    '-.--.': '(', '-.--.-': ')', '_': ' ', '{': '{', '}': '}'
}


def decode_morse(morse_code):
    """Hàm giải mã một chuỗi mã Morse."""
    words = morse_code.strip().split('  ') # Tách các từ (cách nhau bởi 2 space)
    decoded_message = ""
    for word in words:
        letters = word.split(' ') # Tách các ký tự
        for letter in letters:
            if letter in MORSE_TO_CHAR:
                decoded_message += MORSE_TO_CHAR[letter]
        decoded_message += ' ' # Thêm space giữa các từ
    return decoded_message.strip()

# ----- Bắt đầu chương trình chính -----

try:
    # Mở file PDF
    reader = pypdf.PdfReader("lambiresume.pdf")
    
    # Trích xuất toàn bộ văn bản từ tất cả các trang
    full_text = ""
    for page in reader.pages:
        full_text += page.extract_text()

    # Trích xuất chuỗi Morse từ các ký tự Zero-Width
    morse_string = ""
    for char in full_text:
        if char in ZW_TO_MORSE:
            morse_string += ZW_TO_MORSE[char]
            
    if not morse_string:
        print("Không tìm thấy ký tự Zero-Width nào. Kỹ thuật có thể khác.")
    else:
        print("Phát hiện chuỗi Morse ẩn:", morse_string)
        
        # Giải mã chuỗi Morse
        flag = decode_morse(morse_string)
        
        # Thay thế ký tự gạch dưới bằng space nếu cần
        flag = flag.replace(" ", "_")
        
        print("\nFLAG ĐÃ GIẢI MÃ:")
        print(f"deadface{{{flag}}}")

except FileNotFoundError:
    print("Lỗi: Không tìm thấy file 'lambiresume.pdf'.")
except Exception as e:
    print(f"Đã có lỗi xảy ra: {e}")