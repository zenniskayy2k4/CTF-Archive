import socket
import re

HOST = '43.205.113.100'
PORT = 8132

def solve_caesar(ciphertext, key):
    plaintext = ""
    for char in ciphertext:
        if 'a' <= char <= 'z':
            # Dịch chuyển ký tự thường
            shifted = ord(char) + key
            if shifted > ord('z'):
                shifted -= 26
            plaintext += chr(shifted)
        elif 'A' <= char <= 'Z':
            # Dịch chuyển ký tự hoa
            shifted = ord(char) + key
            if shifted > ord('Z'):
                shifted -= 26
            plaintext += chr(shifted)
        else:
            # Giữ nguyên các ký tự khác (dấu cách, dấu câu)
            plaintext += char
    return plaintext

def solve():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        
        while True:
            try:
                # Nhận dữ liệu từ server, giới hạn buffer để không bị treo
                data = s.recv(4096).decode('utf-8')
                print(f"--- SERVER ---\n{data.strip()}")

                if "Question 1:" not in data and "Question 2:" not in data:
                    break

                # Tìm văn bản mã hóa
                encrypted_match = re.search(r"Encrypted: (.*)", data)
                if not encrypted_match:
                    break
                encrypted_text = encrypted_match.group(1)

                # Tìm câu hỏi toán học
                question_match = re.search(r"Question: (.*)", data)
                if not question_match:
                    break
                question_str = question_match.group(1)

                # Chuẩn hóa và giải câu hỏi toán học
                # Thay thế các ký hiệu để eval() có thể hiểu
                math_expr = question_str.replace("= ?", "").strip()
                math_expr = math_expr.replace("What is ", "")
                math_expr = math_expr.replace("?", "")
                
                # eval() có thể nguy hiểm, nhưng trong CTF thì thường chấp nhận được
                key = eval(math_expr)
                
                # Giải mã Caesar
                decrypted_text = solve_caesar(encrypted_text, key)
                
                # Tạo payload và gửi đi
                payload = f"{decrypted_text} | {key}\n"
                print(f"--- SENDING ---\n{payload.strip()}")
                s.sendall(payload.encode('utf-8'))

            except (socket.timeout, ConnectionResetError, BrokenPipeError, IndexError):
                print("Connection closed or error.")
                break
            except Exception as e:
                print(f"An error occurred: {e}")
                break

if __name__ == '__main__':
    solve()