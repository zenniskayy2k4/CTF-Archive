from pwn import *
import subprocess
import re

# --- Cấu hình ---
HOST = "memory.chal.imaginaryctf.org"
PORT = 1337

# --- Danh sách câu trả lời ---
# Tất cả các câu trả lời này đã được xác nhận là đúng từ các lần giải trước
# hoặc từ phân tích logic vững chắc của chúng ta.
answers = {
    1: "rrip",
    2: "6",
    3: "2",
    4: "19",
    5: "18",
    6: "2",
    7: "4096",
    8: "4",
    9: "128",
    10: "ictf{h3x_editors_are_fun}",
    11: "100",
    12: "32",
    13: "4",
    14: "1",
    15: "I3",
    16: "I2",
    17: "WriteEnable"
}

# Bắt đầu kết nối
io = remote(HOST, PORT)

# --- Xử lý Proof of Work (PoW) ---
io.recvuntil(b'You can run the solver with:\n')
io.recvline() # Bỏ qua dòng trống
pow_command_line = io.recvline().strip().decode()
pow_challenge = pow_command_line.split(' ')[-1]
log.info(f"Solving PoW challenge: {pow_challenge}")

# Sử dụng lệnh curl và python để giải PoW
solver_cmd = f"python3 <(curl -sSL https://goo.gle/kctf-pow) solve {pow_challenge}"
result = subprocess.run(solver_cmd, shell=True, capture_output=True, text=True, executable='/bin/bash')

if result.returncode != 0:
    log.error("Failed to solve PoW.")
    log.error(result.stderr)
    exit()

pow_solution = result.stdout.strip()
log.success(f"PoW solution: {pow_solution}")

# Gửi lời giải PoW
io.sendlineafter(b'Solution?', pow_solution.encode())

# --- Vòng lặp trả lời câu hỏi ---
try:
    while True:
        # Nhận câu hỏi
        question_block = io.recvuntil(b'Your answer:').decode()
        print(question_block.strip())

        # Trích xuất số thứ tự câu hỏi
        match = re.search(r'Question (\d+):', question_block)
        if not match:
            log.warning("Could not find question number. Exiting.")
            break
        
        q_num = int(match.group(1))

        if q_num in answers:
            answer = answers[q_num]
            log.info(f"Sending answer for Question {q_num}: {answer}")
            io.sendline(answer.encode())
        else:
            log.error(f"No answer found for Question {q_num}. Exiting.")
            break
            
        # Nhận phản hồi của server
        response = io.recvline().decode().strip()
        print(f"Server response: {response}")
        if "sorry" in response.lower() or "wrong" in response.lower():
            log.error("Incorrect answer. Stopping.")
            break

except EOFError:
    log.success("Quiz finished or connection closed.")
    io.interactive() # Để xem phần output cuối cùng (có thể là flag)

io.close()