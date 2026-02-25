from pwn import *

# Danh sách từ lấy từ source code
words = [
    "biocompatibility", "biodegradability", "characterization", "contraindication",
    "counterbalancing", "counterintuitive", "decentralization", "disproportionate",
    "electrochemistry", "electromagnetism", "environmentalist", "internationality",
    "internationalism", "institutionalize", "microlithography", "microphotography",
    "misappropriation", "mischaracterized", "miscommunication", "misunderstanding",
    "photolithography", "phonocardiograph", "psychophysiology", "rationalizations",
    "representational", "responsibilities", "transcontinental", "unconstitutional"
]

def solve():
    # Kết nối đến server
    host = "penguin.ctf.pascalctf.it"
    port = 5003
    
    print(f"[*] Connecting to {host}:{port}...")
    r = remote(host, port)
    
    # Bỏ qua phần banner mở đầu
    r.recvuntil(b"Welcome to the Penguin's Challenge!")
    
    lookup_table = {}
    
    # Chia danh sách 28 từ thành các nhóm 4 từ (tương ứng với 7 lượt hỏi)
    chunk_size = 4
    word_chunks = [words[i:i + chunk_size] for i in range(0, len(words), chunk_size)]
    
    print("[*] Sending all known words to build lookup table...")
    
    # Gửi từng nhóm từ để lấy bản mã
    for i, chunk in enumerate(word_chunks):
        # Đợi đến lượt nhập
        r.recvuntil(b"Give me 4 words to encrypt")
        
        # Gửi 4 từ
        for j, word in enumerate(chunk):
            r.recvuntil(f"Word {j+1}: ".encode())
            r.sendline(word.encode())
        
        # Nhận kết quả mã hóa
        r.recvuntil(b"Encrypted words: ")
        response_line = r.recvline().decode().strip()
        
        encrypted_chunk = response_line.split(' ')
        
        # Lưu vào bảng tra cứu: Cipher -> Word
        for word, enc in zip(chunk, encrypted_chunk):
            lookup_table[enc] = word

    print("[+] Lookup table built successfully.")
    
    # Nhận đề bài (Ciphertext cần giải)
    r.recvuntil(b"Ciphertext: ")
    challenge_line = r.recvline().decode().strip()
    challenge_ciphers = challenge_line.split(' ')
    
    print(f"[*] Target ciphers: {challenge_line}")
    
    # Giải mã bằng bảng tra cứu
    answers = []
    for cipher in challenge_ciphers:
        if cipher in lookup_table:
            answers.append(lookup_table[cipher])
        else:
            print(f"[-] Error: Found a cipher not in our list! {cipher}")
            return
    
    print(f"[+] Decrypted answers: {answers}")
    
    # Gửi câu trả lời
    for i, ans in enumerate(answers):
        r.recvuntil(f"Guess the word {i+1}: ".encode())
        r.sendline(ans.encode())
        print(f"[*] Submitted word {i+1}: {ans}")
            
    # Nhận Flag
    print("\n[+] Waiting for flag...")
    response = r.recvall()
    print(response.decode())

solve()