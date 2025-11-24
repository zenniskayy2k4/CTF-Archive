import numpy as np
from scipy.io import wavfile
from scipy.fft import fft, fftfreq
from Crypto.Util.number import long_to_bytes, inverse

# Bảng tần số DTMF từ file challenge.py
# Chúng ta sẽ đảo ngược nó để tìm ký tự từ tần số
dtmf_freqs_rev = {
    (697, 1209): '1', (697, 1336): '2', (697, 1477): '3', (697, 1633): 'A',
    (770, 1209): '4', (770, 1336): '5', (770, 1477): '6', (770, 1633): 'B',
    (852, 1209): '7', (852, 1336): '8', (852, 1477): '9', (852, 1633): 'C',
    (941, 1209): '*', (941, 1336): '0', (941, 1477): '#', (941, 1633): 'D',
}
low_freqs = [697, 770, 852, 941]
high_freqs = [1209, 1336, 1477, 1633]

# Hàm tìm tần số gần nhất trong một list
def find_closest_freq(freq, freq_list):
    return min(freq_list, key=lambda x: abs(x - freq))

# Hàm giải mã file WAV chứa tín hiệu DTMF
def decode_dtmf_from_wav(filename, fs=8000, tone_time=0.08, silence_time=0.10):
    # Đọc file wav
    rate, data = wavfile.read(filename)
    if data.dtype != np.float32:
        data = data / 32767.0 # Chuẩn hóa về khoảng [-1, 1]

    # Tính toán độ dài của một tone + một khoảng lặng
    tone_samples = int(fs * tone_time)
    silence_samples = int(fs * silence_time)
    block_samples = tone_samples + silence_samples

    decoded_string = ""
    
    # Duyệt qua file âm thanh theo từng khối
    for i in range(0, len(data), block_samples):
        chunk = data[i : i + tone_samples]
        
        # Bỏ qua nếu chunk quá ngắn hoặc là khoảng lặng
        if len(chunk) < tone_samples or np.max(np.abs(chunk)) < 0.1:
            continue

        # Áp dụng FFT để phân tích tần số
        N = len(chunk)
        yf = fft(chunk)
        xf = fftfreq(N, 1 / fs)

        # Chỉ xét nửa phổ tần dương
        half_n = N // 2
        magnitudes = 2.0/N * np.abs(yf[0:half_n])
        frequencies = xf[0:half_n]

        # Tìm 2 tần số có biên độ lớn nhất
        # Sắp xếp các chỉ số theo biên độ giảm dần
        peak_indices = np.argsort(magnitudes)[::-1]

        # Lấy 2 tần số chính
        f1 = frequencies[peak_indices[0]]
        f2 = frequencies[peak_indices[1]]
        
        # Làm tròn tần số về các giá trị chuẩn của DTMF
        freq1_rounded = find_closest_freq(f1, low_freqs + high_freqs)
        freq2_rounded = find_closest_freq(f2, low_freqs + high_freqs)
        
        # Sắp xếp để khớp với key trong dictionary
        low_f = min(freq1_rounded, freq2_rounded)
        high_f = max(freq1_rounded, freq2_rounded)
        
        # Tìm ký tự tương ứng
        char = dtmf_freqs_rev.get((low_f, high_f))
        if char:
            decoded_string += char
            
    return decoded_string

# --- BƯỚC 1: Giải mã các file WAV ---
print("[+] Decoding WAV files...")
p_str = decode_dtmf_from_wav("p_dial.wav")
q_str = decode_dtmf_from_wav("q_dial.wav")
c_str = decode_dtmf_from_wav("message.wav")

print(f"[*] Decoded p_str (first 20 digits): {p_str[:20]}...")
print(f"[*] Decoded q_str (first 20 digits): {q_str[:20]}...")
print(f"[*] Decoded c_str (first 20 digits): {c_str[:20]}...")

# --- BƯỚC 2: Giải mã RSA ---
print("\n[+] Performing RSA decryption...")

# Chuyển chuỗi thành số nguyên
p = int(p_str)
q = int(q_str)
c = int(c_str)

# Các tham số RSA đã biết
e = 65537

# Tính toán các thành phần của khóa bí mật
n = p * q
phi = (p - 1) * (q - 1)
d = inverse(e, phi)

# Giải mã
m = pow(c, d, n)

# Chuyển số nguyên kết quả thành bytes để đọc flag
flag = long_to_bytes(m)

print(f"\n[+] Decryption successful!")
print(f"[*] Flag: {flag.decode()}")