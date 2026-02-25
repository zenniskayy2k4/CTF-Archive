#!/usr/bin/env python3
from pwn import *
from z3 import *
import itertools
import sys

# Cấu hình kết nối
HOST = 'wordy.ctf.pascalctf.it'
PORT = 5005

# --- Cấu hình Game ---
ALPHABET = "abcdefghijklmnop"
L = 5
K = len(ALPHABET)
N = K ** L

# --- Hàm hỗ trợ từ source ---
def index_to_word(idx: int) -> str:
    digits = []
    x = idx
    for _ in range(L):
        digits.append(x % K)
        x //= K
    letters = [ALPHABET[d] for d in reversed(digits)]
    return "".join(letters)

def word_to_index(word: str) -> int:
    x = 0
    for ch in word:
        d = ALPHABET.find(ch)
        x = x * K + d
    return x

def get_feedback(guess: str, secret: str) -> str:
    res = [None] * L
    secret_counts = {}
    for i in range(L):
        s = secret[i]
        g = guess[i]
        if g == s:
            res[i] = 'G'
        else:
            secret_counts[s] = secret_counts.get(s, 0) + 1
    for i in range(L):
        if res[i] is not None:
            continue
        g = guess[i]
        if secret_counts.get(g, 0) > 0:
            res[i] = 'Y'
            secret_counts[g] -= 1
        else:
            res[i] = '_'
    return ''.join(res)

# --- Class MT19937 Local (để dự đoán sau khi có seed) ---
class MT19937:
    def __init__(self, seed: int):
        self.N = 624
        self.M = 397
        self.mt = [0] * self.N
        self.index = self.N
        self.mt[0] = seed & 0xFFFFFFFF
        for i in range(1, self.N):
            self.mt[i] = (1812433253 * (self.mt[i - 1] ^ (self.mt[i - 1] >> 30)) + i) & 0xFFFFFFFF

    def twist(self):
        N = self.N; M = self.M
        A = 0x9908B0DF
        U = 0x80000000
        L_mask = 0x7FFFFFFF
        for i in range(N):
            y = (self.mt[i] & U) | (self.mt[(i + 1) % N] & L_mask)
            self.mt[i] = self.mt[(i + M) % N] ^ (y >> 1) ^ (A if (y & 1) else 0)
        self.index = 0

    def next_u32(self) -> int:
        if self.index >= self.N:
            self.twist()
        y = self.mt[self.index]
        self.index += 1
        y ^= (y >> 11)
        y ^= ((y << 7) & 0x9D2C5680)
        y ^= ((y << 15) & 0xEFC60000)
        y ^= (y >> 18)
        return y & 0xFFFFFFFF

# --- Z3 Solver để crack Seed ---
def recover_seed_z3(observed_values):
    print(f"[*] Đang dùng Z3 (Optimized) để tìm seed từ {len(observed_values)} giá trị mẫu...")
    
    solver = Solver()
    seed = BitVec('seed', 32)
    
    # --- TỐI ƯU HÓA ---
    # Thay vì loop hết 624, ta chỉ loop đến max_needed
    # Để tính output thứ k (sau twist), ta cần mt[k], mt[k+1] và mt[k+M] (trước twist).
    # Chúng ta thu thập 2 mẫu (index 0 và 1), nên max index cần dùng là 1 + 397 = 398.
    # Ta lấy dư ra một chút cho an toàn (400).
    max_needed = 400 
    
    # 1. Mô phỏng Init (chỉ chạy đến 400 thay vì 624)
    mt = {} # Dùng dict để tiết kiệm memory thay vì list full
    mt[0] = seed
    
    prev = seed
    for i in range(1, max_needed + 1):
        # 1812433253 * (prev ^ (prev >> 30)) + i
        # Tách biểu thức ra để Z3 dễ thở hơn
        xor_val = prev ^ LShR(prev, 30)
        mul_val = 1812433253 * xor_val
        prev = mul_val + i
        mt[i] = prev

    # 2. Mô phỏng Twist & Tempering cho các giá trị quan sát được
    N = 624
    M = 397
    MATRIX_A = 0x9908B0DF
    UPPER_MASK = 0x80000000
    LOWER_MASK = 0x7FFFFFFF

    for obs_idx, obs_val in observed_values:
        # obs_idx là index của output (0, 1, ...)
        # Ta cần tính giá trị mt mới tại vị trí obs_idx
        
        k = obs_idx
        # Cần đảm bảo k+M nằm trong khoảng đã tính toán (k+M <= max_needed)
        if k + M > max_needed:
            print(f"[-] Error: Cần tính thêm mảng mt, max_needed={max_needed} chưa đủ cho index {k}")
            return None

        # Logic Twist cho một phần tử
        y = (mt[k] & UPPER_MASK) | (mt[k + 1] & LOWER_MASK)
        
        mag01 = If((y & 1) == 1, BitVecVal(MATRIX_A, 32), BitVecVal(0, 32))
        
        # mt_new tại vị trí k
        mt_new = mt[k + M] ^ LShR(y, 1) ^ mag01
        
        # Tempering
        y_res = mt_new
        y_res = y_res ^ LShR(y_res, 11)
        y_res = y_res ^ ((y_res << 7) & 0x9D2C5680)
        y_res = y_res ^ ((y_res << 15) & 0xEFC60000)
        y_res = y_res ^ LShR(y_res, 18)
        
        # Ràng buộc: 20 bit cuối phải khớp
        solver.add((y_res & 0xFFFFF) == obs_val)

    print("[*] Đang giải (Solver check)...")
    if solver.check() == sat:
        model = solver.model()
        recovered_seed = model[seed].as_long()
        print(f"[+] Đã tìm thấy Seed: {recovered_seed}")
        return recovered_seed
    else:
        print("[-] Không tìm thấy seed (UNSAT).")
        return None

# --- Logic giải Wordle ---
def solve_wordle_round(r):
    # Tạo danh sách tất cả các từ có thể (chỉ làm 1 lần hoặc filter dần)
    # Để đơn giản và nhanh, ta tạo lại mỗi round (hoặc optimize nếu cần)
    candidates = ["".join(p) for p in itertools.product(ALPHABET, repeat=L)]
    
    r.sendline(b"NEW")
    while True:
        resp = r.recvline().decode().strip()
        if "ROUND STARTED" in resp:
            break
            
    while True:
        # Chọn từ đoán (lấy đầu danh sách candidate)
        guess = candidates[0]
        r.sendline(f"GUESS {guess}".encode())
        
        feedback_line = r.recvline().decode().strip()
        # Format: FEEDBACK G_Y__
        if not feedback_line.startswith("FEEDBACK"):
            print(f"Error reading feedback: {feedback_line}")
            return None
            
        patt = feedback_line.split()[1]
        
        if patt == "GGGGG":
            return guess # Đã tìm ra secret
            
        # Lọc danh sách candidates
        next_candidates = []
        for word in candidates:
            if get_feedback(guess, word) == patt:
                next_candidates.append(word)
        candidates = next_candidates
        
        if not candidates:
            print("Error: No candidates left!")
            return None

def main():
    r = remote(HOST, PORT)
    r.recvuntil(b"READY\n")
    
    observed_data = []
    
    # Chơi 2 ván
    for i in range(2):
        print(f"[*] Round {i+1} collecting data...")
        secret_word = solve_wordle_round(r)
        if not secret_word: return
        secret_idx = word_to_index(secret_word)
        print(f"    -> Index {i+1}: {secret_idx}")
        observed_data.append(secret_idx)
        
    idx1 = observed_data[0]
    idx2 = observed_data[1]
    
    print("\n" + "="*50)
    print(f"[!] Dữ liệu đã thu thập xong.")
    print(f"[!] Hãy mở terminal mới và chạy lệnh C++ sau để tìm seed:")
    print(f"\n    ./crack {idx1} {idx2}\n")
    print("="*50)
    
    seed_input = input("[?] Nhập SEED tìm được từ tool C++ vào đây: ").strip()
    if not seed_input.isdigit():
        print("Invalid seed")
        return
    seed = int(seed_input)

    # Khởi tạo RNG và tiếp tục như cũ
    my_rng = MT19937(seed)
    my_rng.next_u32() # Skip round 1
    my_rng.next_u32() # Skip round 2
    
    print("[*] Seed accepted. Attacking FINAL rounds...")
    for i in range(5):
        out = my_rng.next_u32()
        idx = out & ((1 << 20) - 1)
        next_secret = index_to_word(idx)
        
        print(f"[*] Guessing: {next_secret}")
        r.sendline(f"FINAL {next_secret}".encode())
        
        resp = r.recvline().decode().strip()
        print(f"    Result: {resp}")
        if "{" in resp:
            break

    r.close()

if __name__ == "__main__":
    main()