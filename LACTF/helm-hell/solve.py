import sys

def solve_brainfuck(bf_code):
    # Tape size đủ lớn
    tape = [0] * 30000
    ptr = 0
    
    # Biến để lưu flag tìm được
    flag_chars = []
    
    # Biến theo dõi giá trị tích lũy giữa các lần đọc input
    current_val_at_ptr = 0
    
    # Chúng ta sẽ duyệt qua code BF.
    # Logic: Code chạy -> Gặp dấu phẩy (Input) -> Thực hiện cộng trừ -> Gặp dấu '[' (Check)
    # Tại dấu '[', giá trị tại ptr phải bằng 0.
    # Do đó: (Input_Char + operations) % 256 = 0
    # => Input_Char = (-operations) % 256
    
    # Tìm tất cả các đoạn code nằm giữa các dấu ',' (input)
    # Đoạn đầu tiên là setup, bỏ qua hoặc chạy để init.
    # Tuy nhiên, bài này init pointer loằng ngoằng, ta chỉ quan tâm relative changes.
    
    # Cách đơn giản nhất: Chạy code, khi gặp ',' thì giả định input = 0,
    # sau đó tiếp tục chạy đến '[' đầu tiên. Giá trị tại tape[ptr] lúc đó chính là độ lệch.
    # Input đúng sẽ là (0 - tape[ptr]) % 256.
    
    code_segments = bf_code.split(',')
    
    # Chạy segment đầu tiên (setup môi trường)
    for char in code_segments[0]:
        if char == '>': ptr += 1
        elif char == '<': ptr -= 1
        elif char == '+': tape[ptr] = (tape[ptr] + 1) % 256
        elif char == '-': tape[ptr] = (tape[ptr] - 1) % 256
        # Bỏ qua [ và ] trong đoạn setup vì logic setup có thể phức tạp, 
        # nhưng thường chỉ là init số 0 hoặc dời pointer.
    
    print(f"[*] Setup finished. Start cracking {len(code_segments)-1} chars...")

    for i, segment in enumerate(code_segments[1:]):
        # Tại thời điểm này, lệnh ',' vừa được gọi.
        # Ta giả sử ta nhập số 0 vào ô nhớ này.
        # Thực tế lệnh ',' trong bài này là ghi đè (store), nên giá trị cũ không quan trọng.
        tape[ptr] = 0 
        
        # Chạy các lệnh tiếp theo cho đến khi gặp lệnh kiểm tra '['
        # Lệnh kiểm tra '[' nghĩa là: "Nếu giá trị KHÁC 0 thì thực hiện block lỗi".
        # Để đúng (TRUE), ta KHÔNG được vào block lỗi, tức là giá trị phải BẰNG 0.
        
        relevant_ops = segment.split('[')[0] # Chỉ lấy code từ sau dấu phẩy đến trước dấu [
        
        for char in relevant_ops:
            if char == '>': ptr += 1
            elif char == '<': ptr -= 1
            elif char == '+': tape[ptr] = (tape[ptr] + 1) % 256
            elif char == '-': tape[ptr] = (tape[ptr] - 1) % 256
        
        # Lúc này: (0 + ops) = residue.
        # Để (Input + ops) = 0  => Input = -residue
        
        residue = tape[ptr]
        correct_char_code = (0 - residue) % 256
        char = chr(correct_char_code)
        flag_chars.append(char)
        
        # Cập nhật lại tape để giả lập là ta đã nhập đúng
        tape[ptr] = 0 # Vì logic đúng thì tại '[' giá trị phải là 0
        
        # Xử lý phần còn lại của segment (sau dấu [) để chuẩn bị cho vòng sau
        # Lưu ý: Do ta đã set tape[ptr]=0, vòng lặp [..] sẽ bị bỏ qua (đúng logic BF).
        # Ta chỉ cần xử lý các lệnh sau dấu ] tương ứng.
        # Nhưng code extract của bạn có thể bị lỗi dấu ], nên ta chỉ cần chạy tiếp các lệnh +-<>
        # Bỏ qua nội dung trong [...] vì đó là logic xử lý lỗi.
        
        # Tìm phần code sau dấu ']' đầu tiên (nếu có) để tiếp tục di chuyển pointer cho ký tự tiếp theo
        if ']' in segment:
            remaining_code = segment.split(']', 1)[1]
            for char in remaining_code:
                if char == '>': ptr += 1
                elif char == '<': ptr -= 1
                elif char == '+': tape[ptr] = (tape[ptr] + 1) % 256
                elif char == '-': tape[ptr] = (tape[ptr] - 1) % 256

    print(f"[*] Decoded Flag: {''.join(flag_chars)}")

# Đọc file res.txt
try:
    with open('res.txt', 'r') as f:
        bf_content = f.read()
    solve_brainfuck(bf_content)
except FileNotFoundError:
    print("Lỗi: Không tìm thấy file res.txt. Hãy đảm bảo file này nằm cùng thư mục.")