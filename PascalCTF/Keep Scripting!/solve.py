from pwn import *
import re
import ast

# --- CẤU HÌNH ---
HOST = 'scripting.ctf.pascalctf.it'
PORT = 6004
# TẮT TOÀN BỘ LOG ĐỂ TĂNG TỐC ĐỘ IO
context.log_level = 'error' 

# =============================================================================
# DATA & CONSTANTS (Fix Keypad + Ultimate Data)
# =============================================================================

KEYPAD_COLUMNS = [
    ['Ϙ', 'Ѧ', 'ƛ', 'Ϟ', 'Ѭ', 'ϗ', 'Ͽ'],
    ['Ӭ', 'Ϙ', 'Ͽ', 'Ҩ', '☆', 'ϗ', '¿'],
    ['©', 'Ѽ', 'Ҩ', 'Җ', 'Ԇ', 'ƛ', '☆'],
    ['б', '¶', 'ƀ', 'Ѯ', 'Ѭ', 'Җ', '¿', 'ټ'],
    ['ψ', 'ټ', 'ƀ', 'Ͼ', '¶', 'Ѯ', '★'],
    ['б', 'Ӭ', '҂', 'æ', 'ψ', 'Ҋ', 'Ω']
]

SIMON_MAP = {
    True: { # Vowel
        0: {'red': 'blue', 'blue': 'red', 'green': 'yellow', 'yellow': 'green'},
        1: {'red': 'yellow', 'blue': 'green', 'green': 'blue', 'yellow': 'red'},
        2: {'red': 'green', 'blue': 'red', 'green': 'yellow', 'yellow': 'blue'}
    },
    False: { # No Vowel
        0: {'red': 'blue', 'blue': 'yellow', 'green': 'green', 'yellow': 'red'},
        1: {'red': 'red', 'blue': 'blue', 'green': 'yellow', 'yellow': 'green'},
        2: {'red': 'yellow', 'blue': 'green', 'green': 'blue', 'yellow': 'red'}
    }
}

PASSWORDS = [
    "about", "after", "again", "below", "could", "every", "first", "found", "great", "house",
    "large", "learn", "never", "other", "place", "plant", "point", "question", "right", "small",
    "sound", "spell", "still", "study", "their", "there", "these", "thing", "think", "three",
    "water", "where", "which", "world", "would", "write"
]

WIRE_SEQ_DATA = {
    'red':   ['C', 'B', 'A', 'AC', 'B', 'AC', 'ABC', 'AB', 'B'],
    'blue':  ['B', 'AC', 'B', 'A', 'B', 'BC', 'C', 'AC', 'A'],
    'black': ['ABC', 'AC', 'B', 'AC', 'B', 'BC', 'AB', 'C', 'C']
}

WOF_DISPLAY_MAP = {
    "yes": 2, "first": 1, "display": 5, "okay": 1, "says": 5, "nothing": 2,
    "": 4, "blank": 3, "no": 5, "led": 2, "lead": 5, "read": 3,
    "red": 3, "reed": 4, "leed": 4, "hold on": 5, "you": 3, "you are": 5,
    "your": 3, "you're": 3, "ur": 0, "there": 5, "they're": 4, "their": 2,
    "they are": 2, "see": 5, "c": 1, "cee": 5
}
WOF_LABEL_MAP = {
    "ready": ["yes", "okay", "what", "middle", "left", "press", "right", "blank", "ready"],
    "first": ["left", "okay", "yes", "middle", "no", "right", "nothing", "uhhh", "wait", "ready", "blank", "what", "press", "first"],
    "no": ["blank", "uh huh", "wait", "first", "what", "ready", "right", "yes", "nothing", "left", "press", "okay", "no"],
    "blank": ["wait", "right", "okay", "middle", "blank"],
    "nothing": ["uh huh", "right", "okay", "middle", "yes", "blank", "no", "press", "left", "what", "wait", "first", "nothing"],
    "yes": ["okay", "right", "uh huh", "middle", "first", "what", "press", "ready", "nothing", "yes"],
    "what": ["uh huh", "what"],
    "uh huh": ["uh huh"],
    "left": ["right", "left"],
    "right": ["yes", "nothing", "ready", "press", "no", "wait", "what", "right"],
    "middle": ["blank", "ready", "okay", "what", "nothing", "press", "no", "wait", "left", "middle"],
    "okay": ["middle", "no", "first", "yes", "uh huh", "nothing", "wait", "okay"],
    "wait": ["uh huh", "no", "blank", "okay", "yes", "left", "first", "press", "what", "wait"],
    "press": ["right", "middle", "yes", "ready", "press"],
    "you": ["sure", "you are", "your", "you're", "next", "uh huh", "ur", "hold", "what?", "you"],
    "you are": ["your", "next", "like", "uh huh", "what?", "done", "uh uh", "hold", "you", "u", "you're", "sure", "ur", "you are"],
    "your": ["uh uh", "you are", "uh huh", "your"],
    "you're": ["you", "you're"],
    "ur": ["done", "u", "ur"],
    "u": ["uh huh", "sure", "next", "what?", "you're", "ur", "uh uh", "done", "u"],
    "uh uh": ["ur", "u", "you are", "you're", "next", "uh uh"],
    "what?": ["you", "hold", "you're", "your", "u", "done", "uh uh", "like", "you are", "uh huh", "ur", "next", "what?"],
    "done": ["sure", "uh huh", "next", "what?", "your", "ur", "you're", "hold", "like", "you", "u", "you are", "uh uh", "done"],
    "next": ["what?", "uh huh", "uh uh", "your", "hold", "sure", "next"],
    "hold": ["you are", "u", "done", "uh uh", "you", "ur", "sure", "what?", "you're", "next", "hold"],
    "sure": ["you are", "done", "like", "you're", "you", "hold", "uh huh", "ur", "sure"],
    "like": ["you're", "next", "u", "ur", "hold", "done", "uh uh", "what?", "uh huh", "you", "like"]
}

# =============================================================================
# SOLVER LOGIC
# =============================================================================

def solve_simple_wires(wires, serial_odd):
    num = len(wires)
    wires = [w.lower() for w in wires]
    if num == 3:
        if 'red' not in wires: return 2
        if wires[-1] == 'white': return 3
        if wires.count('blue') > 1: return len(wires) - 1 - wires[::-1].index('blue') + 1
        return 3
    elif num == 4:
        if wires.count('red') > 1 and serial_odd: return len(wires) - 1 - wires[::-1].index('red') + 1
        if wires[-1] == 'yellow' and 'red' not in wires: return 1
        if wires.count('blue') == 1: return 1
        if wires.count('yellow') > 1: return 4
        return 2
    elif num == 5:
        if wires[-1] == 'black' and serial_odd: return 4
        if wires.count('red') == 1 and wires.count('yellow') > 1: return 1
        if 'black' not in wires: return 2
        return 1
    elif num == 6:
        if 'yellow' not in wires and serial_odd: return 3
        if wires.count('yellow') == 1 and wires.count('white') > 1: return 4
        if 'red' not in wires: return 6
        return 4
    return 1

def solve_button(data, batteries, labels):
    color = data.get('color', '').lower()
    text = data.get('text', '').lower()
    strip = data.get('color_strip', '').lower()
    action = 2 
    if color == 'blue' and text == 'abort': action = 2
    elif batteries > 1 and text == 'detonate': action = 1
    elif color == 'white' and 'CAR' in labels: action = 2
    elif batteries > 2 and 'FRK' in labels: action = 1
    elif color == 'yellow': action = 2
    elif color == 'red' and text == 'hold': action = 1
    
    release_digit = 1
    if action == 2:
        if strip == 'blue': release_digit = 4
        elif strip == 'white': release_digit = 1
        elif strip == 'yellow': release_digit = 5
        else: release_digit = 1
    return action, release_digit

def solve_keypads(symbols):
    for col in KEYPAD_COLUMNS:
        if all(s in col for s in symbols):
            mapping = sorted([(i + 1, col.index(s)) for i, s in enumerate(symbols)], key=lambda x: x[1])
            return " ".join([str(x[0]) for x in mapping])
    return "1 2 3 4"

def solve_simon(data, serial_has_vowel, strikes=0):
    flashes = [c.lower() for c in data['colors']]
    mapping = SIMON_MAP[serial_has_vowel][strikes]
    return " ".join([mapping[c] for c in flashes])

def solve_complicated_wires(data, serial_odd, batteries, has_parallel):
    actions = []
    for i in range(data['amount']):
        c = data['colors'][i].lower()
        led = data['leds'][i]
        star = data['stars'][i]
        red, blue = 'red' in c, 'blue' in c
        instr = 'C'
        if red and blue: instr = 'S' if not led and not star else ('D' if led and star else ('S' if led else 'P'))
        elif red: instr = 'S' if not led and not star else ('B' if led else 'C')
        elif blue:
            instr = 'S' if not led and not star else ('P' if led else ('D' if star else 'P'))
            if not red and blue:
                if led and star: instr = 'P'
                elif led: instr = 'P'
                elif star: instr = 'D'
                else: instr = 'S'
        else: instr = 'C' if not led and not star else ('B' if led and star else ('D' if led else 'C'))
            
        cut = False
        if instr == 'C': cut = True
        elif instr == 'D': cut = False
        elif instr == 'S': cut = not serial_odd
        elif instr == 'P': cut = has_parallel
        elif instr == 'B': cut = (batteries >= 2)
        actions.append("cut" if cut else "skip")
    return actions

def solve_wire_sequences(data, history_counts):
    actions = []
    current_wires = data['wires'] 
    for w in current_wires:
        color = w['color'].lower()
        target = w['to'].upper() 
        if color not in WIRE_SEQ_DATA: actions.append('skip'); continue
        count = history_counts[color]
        if count < len(WIRE_SEQ_DATA[color]):
            rule = WIRE_SEQ_DATA[color][count]
            should_cut = target in rule
            actions.append('cut' if should_cut else 'skip')
            history_counts[color] += 1
        else: actions.append('skip') 
    return actions, history_counts

def solve_password(data):
    columns = [ [l.lower() for l in col] for col in data['columns'] ]
    possible = PASSWORDS[:]
    for i in range(5): possible = [w for w in possible if w[i] in columns[i]]
    return possible[0] if possible else "about"

def solve_whos_on_first(data):
    display = data['display'].lower()
    btn_labels = [b.lower() for b in data['buttons']]
    look_idx = WOF_DISPLAY_MAP.get(display, 0)
    target_label = btn_labels[look_idx]
    word_list = WOF_LABEL_MAP.get(target_label, [])
    for w in word_list:
        if w in btn_labels: return w
    return btn_labels[0]

def solve_memory(data, stage, history):
    display = int(data['display'])
    val, pos = 0, 0
    if stage == 1:
        if display == 1: pos = 2
        elif display == 2: pos = 2
        elif display == 3: pos = 3
        elif display == 4: pos = 4
    elif stage == 2:
        if display == 1: val = 4
        elif display == 2: pos = history[0]['pos']
        elif display == 3: pos = 1
        elif display == 4: pos = history[0]['pos']
    elif stage == 3:
        if display == 1: val = history[1]['val']
        elif display == 2: val = history[0]['val']
        elif display == 3: pos = 3
        elif display == 4: val = 4
    elif stage == 4:
        if display == 1: pos = history[0]['pos']
        elif display == 2: pos = 1
        elif display == 3: pos = history[1]['pos']
        elif display == 4: pos = history[1]['pos']
    elif stage == 5:
        if display == 1: val = history[0]['val']
        elif display == 2: val = history[1]['val']
        elif display == 3: val = history[3]['val']
        elif display == 4: val = history[2]['val']
        
    buttons = data.get('buttons', [1,2,3,4]) 
    if val != 0 and pos == 0:
        if val in buttons: pos = buttons.index(val) + 1
    if pos != 0 and val == 0:
        if len(buttons) >= pos: val = buttons[pos-1]
    return {'val': val, 'pos': pos}

# =============================================================================
# MAIN
# =============================================================================

def main():
    print("--- STARTING ULTIMATE SOLVER ---")
    r = remote(HOST, PORT)

    try:
        header = r.recvuntil(b'Module 1/100').decode()
    except:
        header = r.recvall().decode()
        
    serial_match = re.search(r'Serial Number:\s*(\w+)', header)
    serial_num = serial_match.group(1) if serial_match else "000000"
    last_digit = int(re.search(r'\d', serial_num[::-1]).group())
    serial_odd = (last_digit % 2 != 0)
    serial_has_vowel = any(c in 'AEIOU' for c in serial_num.upper())
    
    bat_match = re.search(r'Batteries:\s*(\d+)', header)
    batteries = int(bat_match.group(1)) if bat_match else 0
    
    labels = re.findall(r'Label:\s*(\w+)', header)
    
    ports_match = re.search(r'Ports:\s*(.*)', header)
    ports_str = ports_match.group(1).lower() if ports_match else ""
    has_parallel = "parallel" in ports_str
    
    print(f"[*] Config: Serial={serial_num} | Batt={batteries} | Labels={labels} | Parallel={has_parallel}")

    memory_history = []
    wire_seq_counts = {'red': 0, 'blue': 0, 'black': 0}
    current_module_num = 1
    
    # Kích hoạt module đầu tiên
    r.recvuntil(b'(press Enter):')
    r.sendline(b"")

    while current_module_num <= 100:
        if current_module_num % 10 == 0:
            print(f"Solving Module {current_module_num}...")

        # Đọc dữ liệu (Đọc cho đến khi gặp Dictionary Data)
        buffer = r.recvuntil(b': ').decode()
        while "Data:" not in buffer:
            try:
                buffer += r.recv(1024).decode()
            except EOFError:
                print("EOF Encountered. Printing Buffer:")
                print(buffer)
                return

        data_dict = {}
        data_match = re.search(r"Data:\s*({.*})", buffer)
        if data_match:
            try: data_dict = ast.literal_eval(data_match.group(1))
            except: pass

        # --- LOGIC GỬI ĐÁP ÁN + PRE-EMPTIVE ENTER ---
        # Ta cộng thêm "\n" vào cuối payload để server tự động "ấn Enter" cho module tiếp theo
        # Cẩn thận: sendline() đã tự thêm 1 \n. Ta thêm 1 \n nữa vào string.
        # Tổng cộng server nhận: Answer + \n + \n.
        
        payload = ""

        if "Complicated Wires" in buffer:
            sols = solve_complicated_wires(data_dict, serial_odd, batteries, has_parallel)
            payload = "\n".join(sols) + "\n" # Thêm Enter cuối

        elif "Wire Sequences" in buffer:
            sols, wire_seq_counts = solve_wire_sequences(data_dict, wire_seq_counts)
            payload = "\n".join(sols) + "\n"

        elif "Wires" in buffer: # Simple Wires
            if 'colors' in data_dict:
                ans = solve_simple_wires(data_dict['colors'], serial_odd)
                payload = str(ans) + "\n"

        elif "Button" in buffer:
            action, digit = solve_button(data_dict, batteries, labels)
            if action == 2:
                # Button Hold cần gửi 2 lần
                r.sendline(str(action).encode())
                r.recvuntil(b'digit') 
                payload = str(digit) + "\n"
            else:
                payload = str(action) + "\n"

        elif "Keypads" in buffer:
            ans = solve_keypads(data_dict['symbols'])
            payload = ans + "\n"

        elif "Simon" in buffer:
            ans = solve_simon(data_dict, serial_has_vowel, strikes=0)
            payload = ans + "\n"

        elif "Password" in buffer:
            ans = solve_password(data_dict)
            payload = ans + "\n"
            
        elif "First" in buffer:
            ans = solve_whos_on_first(data_dict)
            payload = ans + "\n"

        elif "Memory" in buffer:
            stage = data_dict.get('stage', 1)
            res = solve_memory(data_dict, stage, memory_history)
            memory_history.append(res)
            # Memory là module đặc biệt, có thể nó không reset "Enter" sau mỗi stage?
            # Thường Memory 5 stage tính là 1 module.
            # Nếu stage < 5, chỉ gửi đáp án. Nếu stage == 5, gửi thêm Enter.
            if stage < 5:
                payload = str(res['val']) # Không thêm Enter thừa
            else:
                payload = str(res['val']) + "\n" # Stage cuối, thêm Enter để qua module

        else:
            print(f"[!] UNKNOWN MODULE: {buffer}")
            payload = "1\n"

        # Gửi Payload
        r.sendline(payload.encode())
        
        # Ở đây ta KHÔNG gọi recvuntil('Enter') nữa vì ta đã gửi trước phím Enter rồi.
        # Server sẽ in ra text, sau đó thấy phím Enter trong buffer và nhảy luôn sang module mới.
        # Vòng lặp tiếp theo sẽ recvuntil(': ') và sẽ hớp luôn phần text thừa đó.
            
        current_module_num += 1

    print("--- FINISHED ---")
    # Chuyển sang interactive để nhận Flag
    r.interactive()

if __name__ == "__main__":
    main()