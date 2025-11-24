from pwn import *
import ast

# --- Cấu hình ---
HOST = "amt.rs"
PORT = 46671

def get_data():
    conn = remote(HOST, PORT)
    
    # Lấy n và e
    line = conn.recvline().decode().strip()
    n_val, e_val = ast.literal_eval(line.replace('n, e = ', ''))
    print(f"n = {n_val}")
    print(f"e = {e_val}")
    
    ciphertexts = []
    for i in range(3):
        try:
            conn.sendlineafter(b'scramble the flag: ', b'0')
            conn.recvline() # Bỏ qua 'scrambling...'
            c_line = conn.recvline().decode().strip()
            c_val = int(c_line.replace('c = ', ''))
            ciphertexts.append(c_val)
            print(f"c{i+1} = {c_val}")
        except EOFError:
            log.error("Mất kết nối. Server có thể đã đóng.")
            exit(1)
            
    conn.close()
    
    # In ra dưới dạng mà SageMath có thể đọc trực tiếp
    print("\n--- Dữ liệu cho SageMath ---")
    print(f"n = {n_val}")
    for i, c in enumerate(ciphertexts):
        print(f"c{i+1} = {c}")

if __name__ == "__main__":
    get_data()