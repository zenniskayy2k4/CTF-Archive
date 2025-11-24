from pwn import *
import re

# Thay đổi HOST và PORT cho phù hợp với đề bài
HOST = 'gacha-gate.chal.idek.team'
PORT = 1337

# Biểu thức chính quy để tách các thành phần trong chuỗi infix
TOKEN_RE = re.compile(r'([0-9]+|[iIl]+|[~&^|()])')

# Độ ưu tiên của các toán tử
PRECEDENCE = {'~': 3, '&': 2, '^': 2, '|': 2}

def infix_to_rpn(expression: str) -> str:
    """
    Chuyển đổi biểu thức infix sang RPN bằng thuật toán Shunting-yard.
    """
    tokens = TOKEN_RE.findall(expression)
    output_queue = []
    operator_stack = []

    for token in tokens:
        if token.isdigit() or re.fullmatch(r'[iIl]+', token):
            output_queue.append(token)
        elif token in PRECEDENCE:
            # Toán tử ~ là toán tử một ngôi và kết hợp từ phải sang trái
            is_right_associative = token == '~'
            while (operator_stack and operator_stack[-1] != '(' and
                   (PRECEDENCE.get(operator_stack[-1], 0) > PRECEDENCE.get(token, 0) or
                    (PRECEDENCE.get(operator_stack[-1], 0) == PRECEDENCE.get(token, 0) and not is_right_associative))):
                output_queue.append(operator_stack.pop())
            operator_stack.append(token)
        elif token == '(':
            operator_stack.append(token)
        elif token == ')':
            while operator_stack and operator_stack[-1] != '(':
                output_queue.append(operator_stack.pop())
            if operator_stack and operator_stack[-1] == '(':
                operator_stack.pop() # Pop dấu '('

    while operator_stack:
        output_queue.append(operator_stack.pop())

    return ' '.join(output_queue)

def solve():
    # Kết nối tới server
    conn = remote(HOST, PORT)
    
    # Đọc dòng chào mừng và biểu thức đầu tiên
    conn.recvuntil(b'lets play a game!\n')
    
    for i in range(50):
        # Nhận biểu thức infix từ server
        line = conn.recvline().decode().strip()
        print(f"Round {i+1}/50")
        print(f"  [S] Received: {line}")
        
        # Chuyển đổi sang RPN
        rpn_expr = infix_to_rpn(line)
        print(f"  [C] Sending:  {rpn_expr}")
        
        # Gửi lại cho server
        conn.sendline(rpn_expr.encode())
        
        # Nhận phản hồi từ server (ví dụ: 'let me see..')
        response = conn.recvline().decode().strip()
        if 'wrong' in response or 'invalid' in response:
            print(f"  [!] Server error: {response}")
            break

    # Sau 50 vòng, server sẽ gửi flag
    try:
        flag = conn.recvline().decode().strip()
        print("\n[+] Flag:", flag)
    except EOFError:
        print("\n[!] Failed to get the flag. Connection closed by server.")
    
    conn.close()

if __name__ == '__main__':
    solve()