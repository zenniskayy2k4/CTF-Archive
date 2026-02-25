from pwn import *
import re
from collections import Counter

# ================= CONFIG =================
HOST = 'chall.polygl0ts.ch'
PORT = 6052
WORDLIST_FILE = "word_list.txt" 
# Lưu ý: File word_list.txt phải là file FULL do đề bài cung cấp (hoặc file 10k từ chuẩn).
# Nếu chỉ dùng đoạn text ngắn ở đầu bài viết thì sẽ không đủ từ.
# ==========================================

# 1. LOAD WORDLIST
try:
    with open(WORDLIST_FILE, "r") as f:
        # Load toàn bộ từ điển để dùng cho việc "đoán mò" kiếm thông tin
        all_words_raw = [line.strip().lower() for line in f if line.strip().isalpha()]
    
    # Chia wordlist theo độ dài để truy xuất nhanh
    words_by_length = {}
    for w in all_words_raw:
        l = len(w)
        if l not in words_by_length: words_by_length[l] = []
        words_by_length[l].append(w)
        
    log.info(f"Loaded {len(all_words_raw)} words.")
except FileNotFoundError:
    log.error(f"Missing {WORDLIST_FILE}")
    exit()

def get_best_guess(candidates, full_dictionary):
    """
    Chọn từ tốt nhất để đoán.
    - Nếu chỉ còn 1-2 từ: Đoán luôn từ đó để thắng.
    - Nếu còn nhiều từ: Chọn từ trong full_dictionary giúp loại trừ tốt nhất (Soft Mode).
    """
    if len(candidates) <= 2:
        return candidates[0]

    # Tính tần suất xuất hiện của từng ký tự trong danh sách ứng viên còn lại
    # Chúng ta muốn chọn từ chứa các ký tự xuất hiện khoảng 50% trong danh sách ứng viên (độ phân chia cao nhất)
    char_counts = Counter()
    for w in candidates:
        char_counts.update(set(w))
    
    total_candidates = len(candidates)
    
    best_word = candidates[0]
    best_score = -1
    
    # Để tối ưu tốc độ, nếu danh sách ứng viên > 100, ta chỉ tìm trong chính ứng viên (Hard Mode nhanh)
    # Nếu danh sách < 100 (đang mắc bẫy), ta tìm trong toàn bộ từ điển (Soft Mode)
    search_space = full_dictionary if len(candidates) < 500 else candidates
    
    # Giới hạn search space ngẫu nhiên nếu quá lớn để tránh timeout
    if len(search_space) > 3000:
        import random
        search_space = random.sample(search_space, 3000)
        # Luôn đảm bảo candidates nằm trong search space
        search_space = list(set(search_space + candidates[:10]))

    for word in search_space:
        score = 0
        unique_chars = set(word)
        for char in unique_chars:
            count = char_counts.get(char, 0)
            if count > 0:
                # Công thức điểm Heuristic: Ưu tiên ký tự chia đôi danh sách (50% true, 50% false)
                # count * (total - count) đạt max khi count = total/2
                score += count * (total_candidates - count)
        
        # Ưu tiên nhẹ cho từ nằm trong danh sách candidates (để có cơ hội trúng luôn)
        if word in candidates:
            score += total_candidates // 10 

        if score > best_score:
            best_score = score
            best_word = word
            
    return best_word

def solve():
    r = remote(HOST, PORT)

    # 2. PARSE STRUCTURE
    try:
        r.recvuntil(b"Structure: ")
        structure_line = r.recvline().decode().strip()
        log.info(f"Structure: {structure_line}")
        
        if '_' in structure_line:
            clean_parts = [re.sub(r'\x1b\[[0-9;]*m', '', p) for p in structure_line.split('_')]
            word_lengths = [len(p) for p in clean_parts]
        else:
            word_lengths = [len(structure_line)]
            
        log.success(f"Detected lengths: {word_lengths}")

    except Exception as e:
        log.error(f"Structure Error: {e}")
        return

    # 3. INIT CANDIDATES
    candidates = []
    for length in word_lengths:
        cands = words_by_length.get(length, [])
        if not cands:
            log.critical(f"No words length {length} found in dictionary!")
            r.close(); return
        candidates.append(cands)

    r.recvuntil(b"Your guess:")

    attempt = 1
    MAX_ATTEMPTS = 6
    
    while True:
        # 4. CHOOSE WORDS
        current_guess_words = []
        for i in range(len(word_lengths)):
            if not candidates[i]:
                log.critical(f"No candidates left for slot {i}!")
                return
            
            # Ở lượt cuối cùng (attempt 6), bắt buộc phải đoán từ trong candidates để hy vọng trúng
            if attempt >= 6:
                current_guess_words.append(candidates[i][0])
            else:
                # Dùng thuật toán chọn từ thông minh
                best_w = get_best_guess(candidates[i], words_by_length.get(word_lengths[i], []))
                current_guess_words.append(best_w)

        guess_str = "".join(current_guess_words).upper()
        pretty_guess = "_".join(current_guess_words)
        
        log.info(f"Attempt {attempt} ({[len(c) for c in candidates]} left): {pretty_guess}")
        r.sendline(guess_str.encode())
        
        # 5. RECEIVE FEEDBACK
        try:
            feedback_line = r.recvline()
            # Check Win
            if b"flag" in feedback_line.lower() or b"{" in feedback_line:
                log.success("FLAG FOUND: " + feedback_line.decode())
                print(r.recvall(timeout=2).decode())
                return
            
            if b'\x1b' not in feedback_line:
                feedback_line = r.recvline()
        except EOFError:
            log.error("Game Over.")
            break

        # 6. FILTER CANDIDATES (STRICT MODE)
        ansi_regex = r"\x1b\[([0-9;]+)m(.)"
        matches = re.findall(ansi_regex, feedback_line.decode())
        
        if not matches: continue

        cleaned_matches = [(col, char) for col, char in matches if char not in ['_', ' ']]
        
        cursor = 0
        for i, length in enumerate(word_lengths):
            word_feedback = cleaned_matches[cursor : cursor + length]
            cursor += length
            
            # Identify Must-Haves
            must_have_chars = set()
            for color, char in word_feedback:
                if '32' in color or '33' in color:
                    must_have_chars.add(char.lower())
            
            new_list = []
            for word in candidates[i]:
                is_valid = True
                for j, (color, char_code) in enumerate(word_feedback):
                    target_char = char_code.lower()
                    word_char = word[j]
                    
                    if '32' in color: # Green
                        if word_char != target_char: is_valid = False; break
                    elif '33' in color: # Yellow
                        if word_char == target_char or target_char not in word: is_valid = False; break
                    else: # Grey
                        if word_char == target_char: is_valid = False; break
                        if target_char not in must_have_chars and target_char in word: is_valid = False; break
                
                if is_valid: new_list.append(word)
            
            candidates[i] = new_list

        attempt += 1

solve()