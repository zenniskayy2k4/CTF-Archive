import base64
import itertools

def solve():
    # --- Bước 1: Tạo bảng ánh xạ (không đổi) ---
    bases = ['A', 'C', 'G', 'T']
    b64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    all_codons = sorted([''.join(p) for p in itertools.product(bases, repeat=3)])
    codon_to_b64_char = {codon: b64_chars[i] for i, codon in enumerate(all_codons)}

    # --- Bước 2: Đọc file FASTA một cách thông minh ---
    dna_sequence = ""
    current_header = ""
    print("[+] Bắt đầu đọc file FASTA và lọc dữ liệu nhiễu...")
    
    try:
        with open('Specimen_512.fasta', 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith(';'):
                    continue
                
                if line.startswith('>'):
                    current_header = line
                    print(f"    Tìm thấy khối: {current_header}")
                    if 'decoy' in current_header.lower():
                        print("    -> Đây là khối nhiễu, bỏ qua.")
                    else:
                        print("    -> Đây là khối dữ liệu, sẽ được xử lý.")
                    continue
                
                # Chỉ thêm dữ liệu nếu header không phải là decoy
                if 'decoy' not in current_header.lower():
                    dna_sequence += line

    except FileNotFoundError:
        print("[-] Lỗi: Không tìm thấy file 'Specimen_512.fasta'.")
        return

    print(f"\n[+] Đã đọc và lọc xong. Tổng chiều dài chuỗi DNA hợp lệ: {len(dna_sequence)} ký tự.")

    # --- Bước 3: Dịch mã (không đổi) ---
    base64_string = ""
    for i in range(0, len(dna_sequence), 3):
        codon = dna_sequence[i:i+3]
        if len(codon) == 3:
            base64_string += codon_to_b64_char[codon]

    # --- Bước 4: Tính toán Padding chính xác và giải mã ---
    
    # Gợi ý gốc là pad_count=2, nhưng hãy tính toán lại cho chắc chắn.
    # Một chuỗi base64 hợp lệ phải có độ dài là bội của 4.
    missing_padding = len(base64_string) % 4
    if missing_padding != 0:
        padded_base64_string = base64_string + '=' * (4 - missing_padding)
        print(f"[+] Chuỗi base64 cần {4 - missing_padding} ký tự padding. Đã thêm.")
    else:
        padded_base64_string = base64_string
        print("[+] Chuỗi base64 không cần padding.")

    try:
        decoded_data = base64.b64decode(padded_base64_string)
        output_filename = "decoded_output_v2.zip"
        with open(output_filename, 'wb') as f:
            f.write(decoded_data)
            
        print(f"\n[SUCCESS] Giải mã thành công! Dữ liệu đã được lưu vào file: {output_filename}")
        print("    Hãy thử giải nén file này.")

    except Exception as e:
        print(f"[-] Lỗi trong quá trình giải mã Base64: {e}")

if __name__ == '__main__':
    solve()